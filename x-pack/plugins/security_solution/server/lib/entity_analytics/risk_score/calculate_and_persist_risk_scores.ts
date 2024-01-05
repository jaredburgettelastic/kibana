/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { ElasticsearchClient, Logger } from '@kbn/core/server';

import type { RiskScoreDataClient } from './risk_score_data_client';
import type { CalculateAndPersistScoresParams, CalculateAndPersistScoresResponse } from '../types';
import type { AssetCriticalityService } from '../asset_criticality/asset_criticality_service';
import { calculateRiskScores } from './calculate_risk_scores';

export const calculateAndPersistRiskScores = async (
  params: CalculateAndPersistScoresParams & {
    assetCriticalityService: AssetCriticalityService;
    esClient: ElasticsearchClient;
    logger: Logger;
    riskScoreDataClient: RiskScoreDataClient;
  }
): Promise<CalculateAndPersistScoresResponse> => {
  const { riskScoreDataClient } = params;

  await riskScoreDataClient.upgrade();

  const { after_keys: afterKeys, scores } = await calculateRiskScores(params);

  if (!scores.host?.length && !scores.user?.length) {
    return { after_keys: {}, errors: [], scores_written: 0 };
  }

  const { errors, docs_written: scoresWritten } = await riskScoreDataClient.writer.bulk(scores);

  return { after_keys: afterKeys, errors, scores_written: scoresWritten };
};
