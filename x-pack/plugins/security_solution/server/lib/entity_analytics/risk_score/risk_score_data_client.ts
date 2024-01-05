/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { Metadata } from '@elastic/elasticsearch/lib/api/typesWithBodyKey';
import type { ClusterPutComponentTemplateRequest } from '@elastic/elasticsearch/lib/api/types';
import {
  createOrUpdateComponentTemplate,
  createOrUpdateIndexTemplate,
} from '@kbn/alerting-plugin/server';
import { mappingFromFieldMap } from '@kbn/alerting-plugin/common';
import type { ElasticsearchClient, Logger, SavedObjectsClientContract } from '@kbn/core/server';

import {
  getIndexPatternDataStream,
  getTransformOptions,
  mappingComponentName,
  riskScoreFieldMap,
  totalFieldsLimit,
} from './configurations';
import type { IIndexPatternString } from '../utils/create_datastream';
import { createDataStream } from '../utils/create_datastream';
import { RiskEngineDataWriter } from './risk_engine_data_writer';
import { getRiskScoreLatestIndex } from '../../../../common/entity_analytics/risk_engine';
import { createTransform, getLatestTransformId } from '../utils/transforms';
import { getRiskInputsIndex } from './get_risk_inputs_index';

import { createOrUpdateIndex } from '../utils/create_or_update_index';

interface RiskScoreDataClientOpts {
  logger: Logger;
  kibanaVersion: string;
  esClient: ElasticsearchClient;
  namespace: string;
  soClient: SavedObjectsClientContract;
}

export class RiskScoreDataClient {
  private alreadyUpgraded = false;
  public writer: RiskEngineDataWriter;
  private readonly indexPatterns: IIndexPatternString;

  constructor(private readonly options: RiskScoreDataClientOpts) {
    this.indexPatterns = getIndexPatternDataStream(options.namespace);
    this.writer = new RiskEngineDataWriter({
      esClient: this.options.esClient,
      namespace: options.namespace,
      index: this.indexPatterns.alias,
      logger: this.options.logger,
    });
  }

  public getRiskInputsIndex = ({ dataViewId }: { dataViewId: string }) =>
    getRiskInputsIndex({
      dataViewId,
      logger: this.options.logger,
      soClient: this.options.soClient,
    });

  public async init() {
    try {
      await this.upsertRiskScoreDataStream();
      await this.upsertRiskScoreLatestIndex();
      await this.upsertRiskScoreLatestIndexTransform();
    } catch (error) {
      this.options.logger.error(`Error initializing risk engine resources: ${error.message}`);
      throw error;
    }
  }

  protected async upsertRiskScoreDataStream() {
    await createOrUpdateComponentTemplate({
      logger: this.options.logger,
      esClient: this.options.esClient,
      template: {
        name: mappingComponentName,
        _meta: {
          managed: true,
        },
        template: {
          settings: {},
          mappings: mappingFromFieldMap(riskScoreFieldMap, 'strict'),
        },
      } as ClusterPutComponentTemplateRequest,
      totalFieldsLimit,
    });

    const indexMetadata: Metadata = {
      kibana: {
        version: this.options.kibanaVersion,
      },
      managed: true,
      namespace: this.options.namespace,
    };

    await createOrUpdateIndexTemplate({
      logger: this.options.logger,
      esClient: this.options.esClient,
      template: {
        name: this.indexPatterns.template,
        body: {
          data_stream: { hidden: true },
          index_patterns: [this.indexPatterns.alias],
          composed_of: [mappingComponentName],
          template: {
            lifecycle: {},
            settings: {
              'index.mapping.total_fields.limit': totalFieldsLimit,
            },
            mappings: {
              dynamic: false,
              _meta: indexMetadata,
            },
          },
          _meta: indexMetadata,
        },
      },
    });

    await createDataStream({
      logger: this.options.logger,
      esClient: this.options.esClient,
      totalFieldsLimit,
      indexPatterns: this.indexPatterns,
    });
  }

  protected async upsertRiskScoreLatestIndex() {
    await createOrUpdateIndex({
      esClient: this.options.esClient,
      logger: this.options.logger,
      options: {
        index: getRiskScoreLatestIndex(this.options.namespace),
        mappings: mappingFromFieldMap(riskScoreFieldMap, false),
      },
    });
  }

  protected async upsertRiskScoreLatestIndexTransform() {
    await createTransform({
      esClient: this.options.esClient,
      logger: this.options.logger,
      transform: {
        transform_id: getLatestTransformId(this.options.namespace),
        ...getTransformOptions({
          dest: getRiskScoreLatestIndex(this.options.namespace),
          source: [this.indexPatterns.alias],
        }),
      },
    });
  }

  /**
   * Ensures that configuration migrations are seamlessly handled across Kibana upgrades.
   * This function is meant to be idempotent. However, to reduce unnecessary processing, it will only execute once
   * across the lifecycle of a {@link RiskScoreDataClient} instance (which is scoped to a single namespace).
   */
  public async upgrade() {
    try {
      if (this.alreadyUpgraded) {
        return;
      }
      this.alreadyUpgraded = true;
      // Migrating to 8.12+ requires a change to the risk score latest transform index's 'dynamic' setting
      await this.upsertRiskScoreLatestIndex();
    } catch (error) {
      this.options.logger.error(`Error upgrading risk engine resources: ${error.message}`);
      this.alreadyUpgraded = false;
      throw error;
    }
  }
}
