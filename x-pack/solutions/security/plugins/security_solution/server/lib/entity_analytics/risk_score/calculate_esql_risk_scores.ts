/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { isEmpty, omit } from 'lodash';
import type { FieldValue, QueryDslQueryContainer } from '@elastic/elasticsearch/lib/api/types';
import type { ElasticsearchClient, Logger } from '@kbn/core/server';
import { fromKueryExpression, toElasticsearchQuery } from '@kbn/es-query';
import {
  ALERT_RISK_SCORE,
  ALERT_WORKFLOW_STATUS,
  ALERT_WORKFLOW_TAGS,
} from '@kbn/rule-registry-plugin/common/technical_rule_data_field_names';
import { toEntries } from 'fp-ts/Record';

import {
  EntityTypeToIdentifierField,
  EntityTypeToEntityIdField,
  EntityType,
} from '../../../../common/entity_analytics/types';
import { getEntityAnalyticsEntityTypes } from '../../../../common/entity_analytics/utils';
import type { ExperimentalFeatures } from '../../../../common';

import type {
  EntityAfterKey,
  EntityRiskScoreRecord,
} from '../../../../common/api/entity_analytics/common';

import { withSecuritySpan } from '../../../utils/with_security_span';
import type { AssetCriticalityService } from '../asset_criticality/asset_criticality_service';

import type { RiskScoresPreviewResponse } from '../../../../common/api/entity_analytics';
import type { CalculateScoresParams, RiskScoreBucket, RiskScoreCompositeBuckets } from '../types';
import { RIEMANN_ZETA_S_VALUE, RIEMANN_ZETA_VALUE } from './constants';
import { filterFromRange } from './helpers';
import { applyScoreModifiers } from './apply_score_modifiers';
import type { PrivmonUserCrudService } from '../privilege_monitoring/users/privileged_users_crud';

/**
 * Generates an ES|QL EVAL clause that computes a unique entity identifier (EUID).
 * The EUID calculation uses a priority-based COALESCE approach to determine the most
 * reliable identifier for each entity type.
 *
 * For users: Uses user.entity.id, user.id, user.email, or a combination of user.name
 * with domain/host context, falling back to user.name.
 *
 * For hosts: Uses host.entity.id, host.id, or a combination of host.name/hostname
 * with domain/mac context, falling back to host.name or host.hostname.
 */
export const generateEUID = (entityType: EntityType): string => {
  if (entityType === EntityType.user) {
    return `EVAL user.entity.id = COALESCE(
                user.entity.id,
                user.id,
                user.email,
                CASE(user.name IS NOT NULL AND user.name != "",
                  CASE(
                    user.domain IS NOT NULL AND user.domain != "", CONCAT(user.name, "@", user.domain),
                    host.id IS NOT NULL AND host.id != "", CONCAT(user.name, "@", host.id),
                    host.domain IS NOT NULL AND host.domain != "", CASE(
                      host.name IS NOT NULL AND host.name != "", CONCAT(user.name, "@", host.name, ".", TO_STRING(host.domain)),
                      host.hostname IS NOT NULL AND host.hostname != "", CONCAT(user.name, "@", host.hostname, ".", TO_STRING(host.domain)),
                      NULL
                    ),
                    host.name IS NOT NULL AND host.name != "", CONCAT(user.name, "@", host.name),
                    host.hostname IS NOT NULL AND host.hostname != "", CONCAT(user.name, "@", host.hostname),
                    NULL
                  ),
                  NULL
                ),
                user.name
            )`;
  } else if (entityType === EntityType.host) {
    return `EVAL host.entity.id = COALESCE(
                host.entity.id,
                host.id,
                CASE(host.domain IS NOT NULL AND host.domain != "",
                  CASE(
                    host.name IS NOT NULL AND host.name != "", CONCAT(host.name, ".", TO_STRING(host.domain)),
                    host.hostname IS NOT NULL AND host.hostname != "", CONCAT(host.hostname, ".", TO_STRING(host.domain)),
                    NULL
                  ),
                  NULL
                ),
                CASE(host.mac IS NOT NULL AND host.mac != "",
                  CASE(
                    host.name IS NOT NULL AND host.name != "", CONCAT(host.name, "|", TO_STRING(host.mac)),
                    host.hostname IS NOT NULL AND host.hostname != "", CONCAT(host.hostname, "|", TO_STRING(host.mac)),
                    NULL
                  ),
                  NULL
                ),
                host.name,
                host.hostname
              )`;
  } else if (entityType === EntityType.service) {
    // Service entities use the standard service.name field
    return `EVAL service.entity.id = COALESCE(service.entity.id, service.name)`;
  }
  // Generic entities already use entity.id as their identifier
  return '';
};

/**
 * Returns the entity identifier field to use for aggregation.
 * For user and host entities, this is the calculated entity.id field.
 * For service entities, it's service.entity.id.
 * For generic entities, it's entity.id.
 */
export const getEntityIdField = (entityType: EntityType): string => {
  return EntityTypeToEntityIdField[entityType];
};

/**
 * Painless helper function that checks if a value is valid (not null and not empty string).
 * This is used as a prefix for the entity ID runtime mapping scripts.
 */
const PAINLESS_IS_VALID_HELPER = `
boolean isValid(def value) {
  if (value == null) {
    return false;
  }
  if (value instanceof String && value.trim().isEmpty()) {
    return false;
  }
  return true;
}
`;

/**
 * Generates a Painless script for computing host.entity.id at runtime.
 * This script calculates a unique identifier for host entities using a priority-based fallback:
 * 1. host.entity.id (if already present)
 * 2. host.id
 * 3. host.name.host.domain
 * 4. host.hostname.host.domain
 * 5. host.name|host.mac
 * 6. host.hostname|host.mac
 * 7. host.hostname
 * 8. host.name
 */
export const getHostEntityIdPainlessScript = (): string => {
  return `
${PAINLESS_IS_VALID_HELPER}
// Check if host.entity.id already exists
if (doc.containsKey('host.entity.id') && doc['host.entity.id'].size() > 0) {
  emit(doc['host.entity.id'].value);
  return;
}

def hostId = doc.containsKey('host.id') && doc['host.id'].size() > 0 ? doc['host.id'].value : null;
def hostName = doc.containsKey('host.name') && doc['host.name'].size() > 0 ? doc['host.name'].value : null;
def hostHostname = doc.containsKey('host.hostname') && doc['host.hostname'].size() > 0 ? doc['host.hostname'].value : null;
def hostDomain = doc.containsKey('host.domain') && doc['host.domain'].size() > 0 ? doc['host.domain'].value : null;
def hostMac = doc.containsKey('host.mac') && doc['host.mac'].size() > 0 ? doc['host.mac'].value : null;

// 2. host.id
if (isValid(hostId)) {
  emit(hostId);
  return;
}
// 3. host.name.host.domain
if (isValid(hostName) && isValid(hostDomain)) {
  emit(hostName + "." + hostDomain);
  return;
}
// 4. host.hostname.host.domain
if (isValid(hostHostname) && isValid(hostDomain)) {
  emit(hostHostname + "." + hostDomain);
  return;
}
// 5. host.name|host.mac
if (isValid(hostName) && isValid(hostMac)) {
  emit(hostName + "|" + hostMac);
  return;
}
// 6. host.hostname|host.mac
if (isValid(hostHostname) && isValid(hostMac)) {
  emit(hostHostname + "|" + hostMac);
  return;
}
// 7. host.hostname
if (isValid(hostHostname)) {
  emit(hostHostname);
  return;
}
// 8. host.name
if (isValid(hostName)) {
  emit(hostName);
  return;
}
// No valid identifier found - emit empty string to avoid null issues
emit("");
`;
};

/**
 * Generates a Painless script for computing user.entity.id at runtime.
 * This script calculates a unique identifier for user entities using a priority-based fallback:
 * 1. user.entity.id (if already present)
 * 2. user.id
 * 3. user.email
 * 4. user.name@user.domain
 * 5. user.name@host.entity.id (computed)
 * 6. user.name
 */
export const getUserEntityIdPainlessScript = (): string => {
  return `
${PAINLESS_IS_VALID_HELPER}
// Check if user.entity.id already exists
if (doc.containsKey('user.entity.id') && doc['user.entity.id'].size() > 0) {
  emit(doc['user.entity.id'].value);
  return;
}

def userId = doc.containsKey('user.id') && doc['user.id'].size() > 0 ? doc['user.id'].value : null;
def userEmail = doc.containsKey('user.email') && doc['user.email'].size() > 0 ? doc['user.email'].value : null;
def userName = doc.containsKey('user.name') && doc['user.name'].size() > 0 ? doc['user.name'].value : null;
def userDomain = doc.containsKey('user.domain') && doc['user.domain'].size() > 0 ? doc['user.domain'].value : null;

// Compute host.entity.id for potential use in user.entity.id
def hostEntityId = null;
if (doc.containsKey('host.entity.id') && doc['host.entity.id'].size() > 0) {
  hostEntityId = doc['host.entity.id'].value;
} else {
  def hostId = doc.containsKey('host.id') && doc['host.id'].size() > 0 ? doc['host.id'].value : null;
  def hostName = doc.containsKey('host.name') && doc['host.name'].size() > 0 ? doc['host.name'].value : null;
  def hostHostname = doc.containsKey('host.hostname') && doc['host.hostname'].size() > 0 ? doc['host.hostname'].value : null;
  def hostDomain = doc.containsKey('host.domain') && doc['host.domain'].size() > 0 ? doc['host.domain'].value : null;
  def hostMac = doc.containsKey('host.mac') && doc['host.mac'].size() > 0 ? doc['host.mac'].value : null;

  if (isValid(hostId)) {
    hostEntityId = hostId;
  } else if (isValid(hostName) && isValid(hostDomain)) {
    hostEntityId = hostName + "." + hostDomain;
  } else if (isValid(hostHostname) && isValid(hostDomain)) {
    hostEntityId = hostHostname + "." + hostDomain;
  } else if (isValid(hostName) && isValid(hostMac)) {
    hostEntityId = hostName + "|" + hostMac;
  } else if (isValid(hostHostname) && isValid(hostMac)) {
    hostEntityId = hostHostname + "|" + hostMac;
  } else if (isValid(hostHostname)) {
    hostEntityId = hostHostname;
  } else if (isValid(hostName)) {
    hostEntityId = hostName;
  }
}

// 2. user.id
if (isValid(userId)) {
  emit(userId);
  return;
}
// 3. user.email
if (isValid(userEmail)) {
  emit(userEmail);
  return;
}
// 4. user.name@user.domain
if (isValid(userName) && isValid(userDomain)) {
  emit(userName + "@" + userDomain);
  return;
}
// 5. user.name@host.entity.id
if (isValid(userName) && isValid(hostEntityId)) {
  emit(userName + "@" + hostEntityId);
  return;
}
// 6. user.name
if (isValid(userName)) {
  emit(userName);
  return;
}
// No valid identifier found - emit empty string to avoid null issues
emit("");
`;
};

/**
 * Generates a Painless script for computing service.entity.id at runtime.
 * This script calculates a unique identifier for service entities using a simple fallback:
 * 1. service.entity.id (if already present)
 * 2. service.name
 */
export const getServiceEntityIdPainlessScript = (): string => {
  return `
// Check if service.entity.id already exists
if (doc.containsKey('service.entity.id') && doc['service.entity.id'].size() > 0) {
  emit(doc['service.entity.id'].value);
  return;
}
if (doc.containsKey('service.name') && doc['service.name'].size() > 0) {
  emit(doc['service.name'].value);
  return;
}
emit("");
`;
};

/**
 * Returns the Painless script for computing the entity ID field for a given entity type.
 */
export const getEntityIdPainlessScript = (entityType: EntityType): string | null => {
  switch (entityType) {
    case EntityType.host:
      return getHostEntityIdPainlessScript();
    case EntityType.user:
      return getUserEntityIdPainlessScript();
    case EntityType.service:
      return getServiceEntityIdPainlessScript();
    case EntityType.generic:
      // Generic entities use entity.id directly, no runtime computation needed
      return null;
    default:
      return null;
  }
};

/**
 * Generates runtime mappings for computing entity IDs for the specified entity types.
 * These mappings are used in composite aggregations to group by computed entity IDs.
 */
export const getEntityIdRuntimeMappings = (
  entityTypes: EntityType[]
): Record<string, { type: string; script: { source: string } }> => {
  const mappings: Record<string, { type: string; script: { source: string } }> = {};

  for (const entityType of entityTypes) {
    const script = getEntityIdPainlessScript(entityType);
    if (script) {
      const fieldName = getEntityIdField(entityType);
      mappings[fieldName] = {
        type: 'keyword',
        script: {
          source: script,
        },
      };
    }
  }

  return mappings;
};

type ESQLResults = Array<
  [EntityType, { scores: EntityRiskScoreRecord[]; afterKey: EntityAfterKey }]
>;

export const calculateScoresWithESQL = async (
  params: {
    assetCriticalityService: AssetCriticalityService;
    privmonUserCrudService: PrivmonUserCrudService;
    esClient: ElasticsearchClient;
    logger: Logger;
    experimentalFeatures: ExperimentalFeatures;
  } & CalculateScoresParams & {
      filters?: Array<{ entity_types: string[]; filter: string }>;
    }
): Promise<RiskScoresPreviewResponse> =>
  withSecuritySpan('calculateRiskScores', async () => {
    const { identifierType, logger, esClient } = params;
    const now = new Date().toISOString();

    const identifierTypes: EntityType[] = identifierType
      ? [identifierType]
      : getEntityAnalyticsEntityTypes();

    // Create separate queries for each entity type with entity-specific filters
    const entityQueries = identifierTypes.map((entityType) => {
      const filter = getFilters(params, entityType);
      return {
        entityType,
        query: getCompositeQuery([entityType], filter, params),
      };
    });

    logger.trace(
      `STEP ONE: Executing ESQL Risk Score queries for entity types: ${identifierTypes.join(', ')}`
    );

    // Execute queries for each entity type
    const responses = await Promise.all(
      entityQueries.map(async ({ entityType, query }) => {
        logger.trace(
          `Executing ESQL Risk Score query for ${entityType}:\n${JSON.stringify(query)}`
        );

        let error: unknown = null;
        const response = await esClient
          .search<never, RiskScoreCompositeBuckets>(query)
          .catch((e) => {
            logger.error(`Error executing composite query for ${entityType}: ${e.message}`);
            error = e;
            return null;
          });

        return {
          entityType,
          response,
          query,
          error,
        };
      })
    );

    // Combine results from all entity queries
    const combinedAggregations: Partial<RiskScoreCompositeBuckets> = {};
    responses.forEach(({ entityType, response }) => {
      if (
        response?.aggregations &&
        (response.aggregations as unknown as Record<string, unknown>)[entityType]
      ) {
        (combinedAggregations as Record<string, unknown>)[entityType] = (
          response.aggregations as unknown as Record<string, unknown>
        )[entityType];
      }
    });

    // Check if all queries that had errors failed due to index_not_found_exception
    const errorsPresent = responses.filter(({ error }) => error).length;
    const indexNotFoundErrors = responses.filter(({ error }) => {
      if (!error) return false;
      const errorMessage = error instanceof Error ? error.message : String(error);
      return (
        errorMessage.includes('index_not_found_exception') ||
        errorMessage.includes('no such index') ||
        errorMessage.includes('NoShardAvailableActionException')
      );
    }).length;

    // If we have no aggregations, return empty scores if:
    // 1. All queries that had errors were index-not-found errors
    // 2. OR there were no errors at all (valid index pattern with no data)
    const shouldReturnEmptyScores =
      errorsPresent === 0 || (errorsPresent > 0 && errorsPresent === indexNotFoundErrors);

    if (Object.keys(combinedAggregations).length === 0) {
      if (shouldReturnEmptyScores) {
        return {
          after_keys: {},
          scores: {
            host: [],
            user: [],
            service: [],
          },
        };
      }
      // Log the actual errors for debugging
      responses.forEach(({ entityType, error }) => {
        if (error) {
          logger.error(
            `Query failed for ${entityType}: ${
              error instanceof Error ? error.message : String(error)
            }`
          );
        }
      });
      // Otherwise, throw an error as before
      throw new Error('No aggregations in any composite response');
    }

    const promises = toEntries(combinedAggregations as Record<string, unknown>).map(
      async ([entityType, aggregationData]: [string, unknown]) => {
        const { buckets, after_key: afterKey } = aggregationData as {
          buckets: Array<{ key: Record<string, string> }>;
          after_key?: Record<string, string>;
        };
        // Use the computed entity ID field for extracting entities from composite buckets
        const entityIdField = getEntityIdField(entityType as EntityType);
        const entities = buckets.map(({ key }) => key[entityIdField]);

        if (entities.length === 0) {
          return Promise.resolve([
            entityType as EntityType,
            { afterKey: afterKey || {}, scores: [] },
          ] satisfies ESQLResults[number]);
        }
        // Use entity ID field for pagination bounds
        const bounds = {
          lower: (params.afterKeys as Record<string, Record<string, string>>)[entityType]?.[
            entityIdField
          ],
          upper: afterKey?.[entityIdField],
        };

        const query = getESQL(
          entityType as EntityType,
          bounds,
          params.alertSampleSizePerShard || 10000,
          params.pageSize,
          params.index
        );

        const entityFilter = getFilters(params, entityType as EntityType);
        return esClient.esql
          .query({
            query,
            filter: { bool: { filter: entityFilter } },
          })
          .then((rs) => rs.values.map(buildRiskScoreBucket(entityType as EntityType, params.index)))

          .then(async (riskScoreBuckets) => {
            const results = await applyScoreModifiers({
              now,
              experimentalFeatures: params.experimentalFeatures,
              identifierType: entityType as EntityType,
              deps: {
                assetCriticalityService: params.assetCriticalityService,
                privmonUserCrudService: params.privmonUserCrudService,
                logger,
              },
              weights: params.weights,
              page: {
                buckets: riskScoreBuckets,
                bounds,
                // Use the new entity ID field for risk score storage
                identifierField: getEntityIdField(entityType as EntityType),
              },
            });

            return results;
          })
          .then((scores: EntityRiskScoreRecord[]): ESQLResults[number] => {
            return [
              entityType as EntityType,
              {
                scores,
                afterKey: afterKey as EntityAfterKey,
              },
            ];
          })

          .catch((error) => {
            logger.error(
              `Error executing ESQL query for entity type ${entityType}: ${error.message}`
            );
            logger.error(`Query: ${query}`);
            return [
              entityType as EntityType,
              { afterKey: afterKey || {}, scores: [] },
            ] satisfies ESQLResults[number];
          });
      }
    );
    const esqlResults = await Promise.all(promises);

    const results: RiskScoresPreviewResponse = esqlResults.reduce<RiskScoresPreviewResponse>(
      (res, [entityType, { afterKey, scores }]) => {
        res.after_keys[entityType] = afterKey || {};
        res.scores[entityType] = scores;
        return res;
      },
      { after_keys: {}, scores: {} }
    );

    return results;
  });

const getFilters = (options: CalculateScoresParams, entityType?: EntityType) => {
  const {
    excludeAlertStatuses = [],
    excludeAlertTags = [],
    range,
    filter: userFilter,
    filters: customFilters,
  } = options;
  const filters = [filterFromRange(range), { exists: { field: ALERT_RISK_SCORE } }];
  if (excludeAlertStatuses.length > 0) {
    filters.push({
      bool: { must_not: { terms: { [ALERT_WORKFLOW_STATUS]: excludeAlertStatuses } } },
    });
  }
  if (!isEmpty(userFilter)) {
    filters.push(userFilter as QueryDslQueryContainer);
  }
  if (excludeAlertTags.length > 0) {
    filters.push({
      bool: { must_not: { terms: { [ALERT_WORKFLOW_TAGS]: excludeAlertTags } } },
    });
  }

  // Apply entity-specific custom filters (EXCLUSIVE - exclude matching alerts)
  if (customFilters && customFilters.length > 0 && entityType) {
    customFilters
      .filter((customFilter) => customFilter.entity_types.includes(entityType))
      .forEach((customFilter) => {
        try {
          const kqlQuery = fromKueryExpression(customFilter.filter);
          const esQuery = toElasticsearchQuery(kqlQuery);
          if (esQuery) {
            filters.push({
              bool: { must: esQuery },
            });
          }
        } catch (error) {
          // Silently ignore invalid KQL filters to prevent query failures
        }
      });
  }

  return filters;
};

export const getCompositeQuery = (
  entityTypes: EntityType[],
  filter: QueryDslQueryContainer[],
  params: CalculateScoresParams
) => {
  // Generate runtime mappings for computing entity IDs
  const entityIdRuntimeMappings = getEntityIdRuntimeMappings(entityTypes);

  // Merge with any existing runtime mappings from params
  const mergedRuntimeMappings = {
    ...params.runtimeMappings,
    ...entityIdRuntimeMappings,
  };

  return {
    size: 0,
    index: params.index,
    ignore_unavailable: true,
    runtime_mappings: mergedRuntimeMappings,
    query: {
      function_score: {
        query: {
          bool: {
            filter,
            should: [
              {
                match_all: {}, // This forces ES to calculate score
              },
            ],
          },
        },
        field_value_factor: {
          field: ALERT_RISK_SCORE, // sort by risk score
        },
      },
    },
    aggs: entityTypes.reduce((aggs, entityType) => {
      // Use the computed entity ID field for aggregation
      const entityIdField = getEntityIdField(entityType);
      return {
        ...aggs,
        [entityType]: {
          composite: {
            size: params.pageSize,
            sources: [{ [entityIdField]: { terms: { field: entityIdField } } }],
            after: params.afterKeys[entityType],
          },
        },
      };
    }, {}),
  };
};

export const getESQL = (
  entityType: EntityType,
  afterKeys: {
    lower?: string;
    upper?: string;
  },
  sampleSize: number,
  pageSize: number,
  index: string = '.alerts-security.alerts-default'
) => {
  // Use the new entity ID field for both filtering and aggregation
  const entityIdField = getEntityIdField(entityType);
  // Generate the EUID calculation clause
  const euidClause = generateEUID(entityType);

  // Build the range filter using entity ID (which is computed before this filter is applied)
  const lower = afterKeys.lower ? `${entityIdField} > "${afterKeys.lower}"` : undefined;
  const upper = afterKeys.upper ? `${entityIdField} <= "${afterKeys.upper}"` : undefined;
  if (!lower && !upper) {
    throw new Error('Either lower or upper after key must be provided for pagination');
  }
  const rangeClause = [lower, upper].filter(Boolean).join(' AND ');

  const query = /* SQL */ `
  FROM ${index} METADATA _index
    | WHERE kibana.alert.risk_score IS NOT NULL
    | RENAME kibana.alert.risk_score as risk_score,
             kibana.alert.rule.name as rule_name,
             kibana.alert.rule.uuid as rule_id,
             kibana.alert.uuid as alert_id,
             event.kind as category,
             @timestamp as time
    | ${euidClause}
    | WHERE ${rangeClause}
    | EVAL rule_name_b64 = TO_BASE64(rule_name),
           category_b64 = TO_BASE64(category)
    | EVAL input = CONCAT(""" {"risk_score": """", risk_score::keyword, """", "time": """", time::keyword, """", "index": """", _index, """", "rule_name_b64": """", rule_name_b64, """\", "category_b64": """", category_b64, """\", "id": \"""", alert_id, """\" } """)
    | STATS
        alert_count = count(risk_score),
        scores = MV_PSERIES_WEIGHTED_SUM(TOP(risk_score, ${sampleSize}, "desc"), ${RIEMANN_ZETA_S_VALUE}),
        risk_inputs = TOP(input, 10, "desc")
    BY ${entityIdField}
    | SORT scores DESC
    | LIMIT ${pageSize}
  `;

  return query;
};

export const buildRiskScoreBucket =
  (entityType: EntityType, index: string) =>
  (row: FieldValue[]): RiskScoreBucket => {
    const [count, score, _inputs, entity] = row as [
      number,
      number,
      string | string[], // ES Multivalue nonsense: if it's just one value we get the value, if it's multiple we get an array
      string
    ];

    const inputs = (Array.isArray(_inputs) ? _inputs : [_inputs]).map((input, i) => {
      let parsedRiskInputData = JSON.parse('{}');
      let ruleName: string | undefined;
      let category: string | undefined;

      try {
        // Parse JSON and decode Base64 encoded fields to handle special characters (quotes, backslashes, newlines, etc.)
        parsedRiskInputData = JSON.parse(input);

        ruleName = parsedRiskInputData.rule_name_b64
          ? Buffer.from(parsedRiskInputData.rule_name_b64, 'base64').toString('utf-8')
          : parsedRiskInputData.rule_name; // Fallback for backward compatibility
        category = parsedRiskInputData.category_b64
          ? Buffer.from(parsedRiskInputData.category_b64, 'base64').toString('utf-8')
          : parsedRiskInputData.category; // Fallback for backward compatibility
      } catch {
        // Attempt to use fallback values if parsedRiskInputData was parsed but decoding failed
        if (parsedRiskInputData && Object.keys(parsedRiskInputData).length > 0) {
          ruleName = parsedRiskInputData.rule_name;
          category = parsedRiskInputData.category;
        }
      }

      const value = parseFloat(parsedRiskInputData.risk_score);
      const currentScore = value / Math.pow(i + 1, RIEMANN_ZETA_S_VALUE);
      const otherFields = omit(parsedRiskInputData, [
        'risk_score',
        'rule_name',
        'rule_name_b64',
        'category',
        'category_b64',
      ]);

      return {
        id: parsedRiskInputData.id,
        ...otherFields,
        rule_name: ruleName,
        category,
        score: value,
        contribution: currentScore / RIEMANN_ZETA_VALUE,
        index,
      };
    });

    // Use the new entity ID field for the bucket key
    const entityIdField = getEntityIdField(entityType);

    return {
      key: { [entityIdField]: entity },
      doc_count: count,
      top_inputs: {
        doc_count: inputs.length,
        risk_details: {
          value: {
            score,
            normalized_score: score / RIEMANN_ZETA_VALUE, // normalize value to be between 0-100
            notes: [],
            category_1_score: score, // Don't normalize here - will be normalized in calculate_risk_scores.ts
            category_1_count: count,
            risk_inputs: inputs,
          },
        },
      },
    };
  };
