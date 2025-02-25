/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { DETECTION_ENGINE_RULES_BULK_DELETE } from '../../../../../../../common/constants';
import {
  getEmptyFindResult,
  getFindResultWithSingleHit,
  getDeleteBulkRequest,
  getDeleteBulkRequestById,
  getDeleteAsPostBulkRequest,
  getDeleteAsPostBulkRequestById,
  getEmptySavedObjectsResponse,
} from '../../../../routes/__mocks__/request_responses';
import { requestContextMock, serverMock, requestMock } from '../../../../routes/__mocks__';
import { bulkDeleteRulesRoute } from './route';
import { loggingSystemMock, docLinksServiceMock } from '@kbn/core/server/mocks';

describe('Bulk delete rules route', () => {
  let server: ReturnType<typeof serverMock.create>;
  let { clients, context } = requestContextMock.createTools();

  beforeEach(() => {
    server = serverMock.create();
    ({ clients, context } = requestContextMock.createTools());
    const logger = loggingSystemMock.createLogger();
    const docLinks = docLinksServiceMock.createSetupContract();

    clients.rulesClient.find.mockResolvedValue(getFindResultWithSingleHit()); // rule exists
    clients.rulesClient.delete.mockResolvedValue({}); // successful deletion
    clients.savedObjectsClient.find.mockResolvedValue(getEmptySavedObjectsResponse()); // rule status request

    bulkDeleteRulesRoute(server.router, logger, docLinks);
  });

  describe('status codes with actionClient and alertClient', () => {
    test('returns 200 when deleting a single rule with a valid actionClient and alertClient by alertId', async () => {
      const response = await server.inject(
        getDeleteBulkRequest(),
        requestContextMock.convertContext(context)
      );
      expect(response.status).toEqual(200);
    });

    test('returns 200 when deleting a single rule and related rule status', async () => {
      const response = await server.inject(
        getDeleteBulkRequest(),
        requestContextMock.convertContext(context)
      );
      expect(response.status).toEqual(200);
    });

    test('returns 200 when deleting a single rule with a valid actionClient and alertClient by alertId using POST', async () => {
      const response = await server.inject(
        getDeleteAsPostBulkRequest(),
        requestContextMock.convertContext(context)
      );
      expect(response.status).toEqual(200);
    });

    test('returns 200 when deleting a single rule with a valid actionClient and alertClient by id', async () => {
      const response = await server.inject(
        getDeleteBulkRequestById(),
        requestContextMock.convertContext(context)
      );
      expect(response.status).toEqual(200);
    });

    test('returns 200 when deleting a single rule with a valid actionClient and alertClient by id using POST', async () => {
      const response = await server.inject(
        getDeleteAsPostBulkRequestById(),
        requestContextMock.convertContext(context)
      );
      expect(response.status).toEqual(200);
    });

    test('returns 200 because the error is in the payload when deleting a single rule that does not exist with a valid actionClient and alertClient', async () => {
      clients.rulesClient.find.mockResolvedValue(getEmptyFindResult());
      const response = await server.inject(
        getDeleteBulkRequest(),
        requestContextMock.convertContext(context)
      );
      expect(response.status).toEqual(200);
    });

    test('returns 404 in the payload when deleting a single rule that does not exist with a valid actionClient and alertClient', async () => {
      clients.rulesClient.find.mockResolvedValue(getEmptyFindResult());

      const response = await server.inject(
        getDeleteBulkRequest(),
        requestContextMock.convertContext(context)
      );
      expect(response.status).toEqual(200);
      expect(response.body).toEqual(
        expect.arrayContaining([
          {
            error: { message: 'rule_id: "rule-1" not found', status_code: 404 },
            rule_id: 'rule-1',
          },
        ])
      );
    });
  });

  describe('request validation', () => {
    test('rejects requests without IDs', async () => {
      const request = requestMock.create({
        method: 'post',
        path: DETECTION_ENGINE_RULES_BULK_DELETE,
        body: [{}],
      });
      const response = await server.inject(request, requestContextMock.convertContext(context));
      expect(response.status).toEqual(200);
      expect(response.body).toEqual([
        {
          error: { message: 'either "id" or "rule_id" must be set', status_code: 400 },
          rule_id: '(unknown id)',
        },
      ]);
    });

    test('rejects requests with both id and rule_id', async () => {
      const request = requestMock.create({
        method: 'post',
        path: DETECTION_ENGINE_RULES_BULK_DELETE,
        body: [{ id: 'c1e1b359-7ac1-4e96-bc81-c683c092436f', rule_id: 'rule_1' }],
      });
      const response = await server.inject(request, requestContextMock.convertContext(context));
      expect(response.status).toEqual(200);
      expect(response.body).toEqual([
        {
          error: {
            message: 'both "id" and "rule_id" cannot exist, choose one or the other',
            status_code: 400,
          },
          rule_id: 'c1e1b359-7ac1-4e96-bc81-c683c092436f',
        },
      ]);
    });
  });
});
