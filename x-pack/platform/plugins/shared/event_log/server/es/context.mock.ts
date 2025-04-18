/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { loggingSystemMock } from '@kbn/core/server/mocks';

import type { EsContext } from './context';
import { namesMock } from './names.mock';
import type { IClusterClientAdapter } from './cluster_client_adapter';
import { clusterClientAdapterMock } from './cluster_client_adapter.mock';

export const MOCK_RETRY_DELAY = 20;

const createContextMock = () => {
  const mock: jest.Mocked<EsContext> & {
    esAdapter: jest.Mocked<IClusterClientAdapter>;
  } = {
    logger: loggingSystemMock.createLogger(),
    esNames: namesMock.create(),
    shouldSetExistingAssetsToHidden: true,
    initialize: jest.fn(),
    shutdown: jest.fn(),
    waitTillReady: jest.fn(async () => true),
    esAdapter: clusterClientAdapterMock.create(),
    initialized: true,
    retryDelay: MOCK_RETRY_DELAY,
  };
  return mock;
};

export const contextMock = {
  create: createContextMock,
};
