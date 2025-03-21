/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { estypes } from '@elastic/elasticsearch';
import type { IScopedClusterClient } from '@kbn/core/server';
import type { DataViewsService, DataView } from '@kbn/data-views-plugin/common';
import type { RollupFields } from '@kbn/ml-anomaly-utils';
import { DataViewType } from '@kbn/data-views-plugin/common';

export interface RollupJob {
  job_id: string;
  rollup_index: string;
  index_pattern: string;
  fields: RollupFields;
}

export async function rollupServiceProvider(
  indexPattern: string,
  { asCurrentUser }: IScopedClusterClient,
  dataViewsService: DataViewsService
) {
  const rollupIndexPatternObject = await loadRollupIndexPattern(indexPattern, dataViewsService);
  let jobIndexPatterns: string[] = [indexPattern];

  async function getRollupJobs(): Promise<
    estypes.RollupGetRollupCapsRollupCapabilitySummary[] | null
  > {
    if (
      rollupIndexPatternObject !== null &&
      rollupIndexPatternObject.typeMeta?.params !== undefined
    ) {
      const rollUpIndex: string = rollupIndexPatternObject.typeMeta.params.rollup_index;
      const rollupCaps = await asCurrentUser.rollup.getRollupIndexCaps(
        {
          index: rollUpIndex,
        },
        { maxRetries: 0 }
      );

      const indexRollupCaps = rollupCaps[rollUpIndex];
      if (indexRollupCaps && indexRollupCaps.rollup_jobs) {
        jobIndexPatterns = indexRollupCaps.rollup_jobs.map((j) => j.index_pattern);

        return indexRollupCaps.rollup_jobs;
      }
    }

    return null;
  }

  function getIndexPattern() {
    return jobIndexPatterns.join(',');
  }

  return {
    getRollupJobs,
    getIndexPattern,
  };
}

async function loadRollupIndexPattern(
  indexPattern: string,
  dataViewsService: DataViewsService
): Promise<DataView | null> {
  const resp = await dataViewsService.find('*', 10000);
  const obj = resp.find(
    (dv) =>
      dv.type === DataViewType.ROLLUP && dv.title === indexPattern && dv.typeMeta !== undefined
  );

  return obj ?? null;
}
