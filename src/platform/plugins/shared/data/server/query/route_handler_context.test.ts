/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import { coreMock } from '@kbn/core/server/mocks';
import { FilterStateStore, Query } from '@kbn/es-query';
import { DATA_VIEW_SAVED_OBJECT_TYPE } from '../../common';
import type { SavedObject, SavedQueryAttributes } from '../../common';
import {
  InternalSavedQueryAttributes,
  registerSavedQueryRouteHandlerContext,
} from './route_handler_context';
import { SavedObjectsFindResponse, SavedObjectsUpdateResponse } from '@kbn/core/server';

const mockContext = {
  core: coreMock.createRequestHandlerContext(),
};
const {
  core: {
    savedObjects: { client: mockSavedObjectsClient },
  },
} = mockContext;

const savedQueryAttributes: SavedQueryAttributes = {
  title: 'foo',
  description: 'bar',
  query: {
    language: 'kuery',
    query: 'response:200',
  },
  filters: [],
};
const internalSavedQueryAttributes: InternalSavedQueryAttributes = {
  ...savedQueryAttributes,
  titleKeyword: 'foo',
};
const savedQueryAttributesBar: SavedQueryAttributes = {
  title: 'bar',
  description: 'baz',
  query: {
    language: 'kuery',
    query: 'response:200',
  },
};

const savedQueryAttributesWithFilters: SavedQueryAttributes = {
  ...savedQueryAttributes,
  filters: [
    {
      query: { match_all: {} },
      $state: { store: FilterStateStore.APP_STATE },
      meta: {
        index: 'my-index',
        disabled: false,
        negate: false,
        alias: null,
      },
    },
  ],
  timefilter: {
    to: 'now',
    from: 'now-15m',
    refreshInterval: {
      pause: false,
      value: 0,
    },
  },
};

const savedQueryReferences = [
  {
    type: DATA_VIEW_SAVED_OBJECT_TYPE,
    name: 'my-index',
    id: 'my-index',
  },
];

describe('saved query route handler context', () => {
  let context: Awaited<ReturnType<typeof registerSavedQueryRouteHandlerContext>>;

  beforeEach(async () => {
    context = await registerSavedQueryRouteHandlerContext(
      coreMock.createCustomRequestHandlerContext({
        core: mockContext.core,
      })
    );

    mockSavedObjectsClient.create.mockClear();
    mockSavedObjectsClient.resolve.mockClear();
    mockSavedObjectsClient.find.mockClear();
    mockSavedObjectsClient.delete.mockClear();
  });

  describe('create', function () {
    it('should create a saved object for the given attributes', async () => {
      const mockResponse: SavedObject<InternalSavedQueryAttributes> = {
        id: 'foo',
        type: 'query',
        attributes: internalSavedQueryAttributes,
        references: [],
      };
      mockSavedObjectsClient.find.mockResolvedValue({
        total: 0,
        page: 0,
        per_page: 0,
        saved_objects: [],
      });
      mockSavedObjectsClient.create.mockResolvedValue(mockResponse);

      const response = await context.create(savedQueryAttributes);

      expect(mockSavedObjectsClient.create).toHaveBeenCalledWith(
        'query',
        { ...internalSavedQueryAttributes, timefilter: null },
        {
          references: [],
        }
      );
      expect(response).toEqual({
        id: 'foo',
        attributes: savedQueryAttributes,
      });
    });

    it('should optionally accept query in object format', async () => {
      const savedQueryAttributesWithQueryObject: SavedQueryAttributes = {
        ...savedQueryAttributes,
        query: {
          language: 'lucene',
          query: { match_all: {} },
        },
      };
      const mockResponse: SavedObject<InternalSavedQueryAttributes> = {
        id: 'foo',
        type: 'query',
        attributes: {
          ...savedQueryAttributesWithQueryObject,
          titleKeyword: 'foo',
        },
        references: [],
      };
      mockSavedObjectsClient.find.mockResolvedValue({
        total: 0,
        page: 0,
        per_page: 0,
        saved_objects: [],
      });
      mockSavedObjectsClient.create.mockResolvedValue(mockResponse);

      const result = await context.create(savedQueryAttributesWithQueryObject);

      expect(result).toEqual({
        id: 'foo',
        attributes: savedQueryAttributesWithQueryObject,
      });
    });

    it('should optionally accept filters and timefilters in object format', async () => {
      const serializedSavedQueryAttributesWithFilters = {
        ...savedQueryAttributesWithFilters,
        filters: savedQueryAttributesWithFilters.filters,
        timefilter: savedQueryAttributesWithFilters.timefilter,
      };
      const mockResponse: SavedObject<InternalSavedQueryAttributes> = {
        id: 'foo',
        type: 'query',
        attributes: {
          ...serializedSavedQueryAttributesWithFilters,
          titleKeyword: 'foo',
        },
        references: [],
      };
      mockSavedObjectsClient.find.mockResolvedValue({
        total: 0,
        page: 0,
        per_page: 0,
        saved_objects: [],
      });
      mockSavedObjectsClient.create.mockResolvedValue(mockResponse);

      await context.create(savedQueryAttributesWithFilters);

      const [[type, attributes]] = mockSavedObjectsClient.create.mock.calls;
      const { filters = [], timefilter } = attributes as SavedQueryAttributes;
      expect(type).toEqual('query');
      expect(filters.length).toBe(1);
      expect(timefilter).toEqual(savedQueryAttributesWithFilters.timefilter);
    });

    it('should throw an error when saved objects client returns error', async () => {
      mockSavedObjectsClient.find.mockResolvedValue({
        total: 0,
        page: 0,
        per_page: 0,
        saved_objects: [],
      });
      mockSavedObjectsClient.create.mockResolvedValue({
        error: {
          error: '123',
          message: 'An Error',
        },
      } as SavedObject);

      const response = context.create(savedQueryAttributes);

      await expect(response).rejects.toMatchInlineSnapshot(`[Error: An Error]`);
    });

    it('should throw an error if the saved query does not have a title', async () => {
      const response = context.create({ ...savedQueryAttributes, title: '' });
      await expect(response).rejects.toMatchInlineSnapshot(
        `[Error: Cannot create query without a title]`
      );
    });
  });

  describe('update', function () {
    beforeEach(() => {
      mockSavedObjectsClient.find.mockResolvedValue({
        total: 0,
        page: 0,
        per_page: 0,
        saved_objects: [],
      });
    });

    describe('when the saved query does not have namespaces', () => {
      it('should update a saved object for the given attributes', async () => {
        // Given
        const mockResponse: SavedObject<InternalSavedQueryAttributes> = {
          id: 'foo',
          type: 'query',
          attributes: internalSavedQueryAttributes,
          references: [],
        };
        mockSavedObjectsClient.update.mockResolvedValue(mockResponse);

        // When
        const response = await context.update('foo', savedQueryAttributes);

        // Then
        expect(mockSavedObjectsClient.update).toHaveBeenCalledWith(
          'query',
          'foo',
          { ...internalSavedQueryAttributes, timefilter: null },
          {
            references: [],
          }
        );
        expect(response).toEqual({
          id: 'foo',
          attributes: savedQueryAttributes,
        });
      });
    });

    describe('when the saved query has namespaces', () => {
      it('should update a saved object for the given attributes', async () => {
        // Given
        const mockResponse: SavedObject<InternalSavedQueryAttributes> = {
          id: 'foo',
          type: 'query',
          attributes: internalSavedQueryAttributes,
          references: [],
          namespaces: ['default'],
        };
        mockSavedObjectsClient.update.mockResolvedValue(mockResponse);

        // When
        const response = await context.update('foo', savedQueryAttributes);

        // Then
        expect(mockSavedObjectsClient.update).toHaveBeenCalledWith(
          'query',
          'foo',
          { ...internalSavedQueryAttributes, timefilter: null },
          {
            references: [],
          }
        );
        expect(response).toEqual({
          id: 'foo',
          attributes: savedQueryAttributes,
          namespaces: ['default'],
        });
      });
    });

    it('should throw an error when saved objects client returns error', async () => {
      mockSavedObjectsClient.find.mockResolvedValue({
        total: 0,
        page: 0,
        per_page: 0,
        saved_objects: [],
      });
      mockSavedObjectsClient.update.mockResolvedValue({
        error: {
          error: '123',
          message: 'An Error',
        },
      } as SavedObjectsUpdateResponse);

      const response = context.update('foo', savedQueryAttributes);

      await expect(response).rejects.toMatchInlineSnapshot(`[Error: An Error]`);
    });

    it('should throw an error if the saved query does not have a title', async () => {
      const response = context.create({ ...savedQueryAttributes, title: '' });
      await expect(response).rejects.toMatchInlineSnapshot(
        `[Error: Cannot create query without a title]`
      );
    });
  });

  describe('find', function () {
    it('should find and return saved queries without search text or pagination parameters', async () => {
      const mockResponse: SavedObjectsFindResponse<SavedQueryAttributes> = {
        page: 0,
        per_page: 0,
        saved_objects: [
          {
            id: 'foo',
            type: 'query',
            score: 0,
            attributes: savedQueryAttributes,
            references: [],
          },
        ],
        total: 5,
      };
      mockSavedObjectsClient.find.mockResolvedValue(mockResponse);

      const response = await context.find();

      expect(mockSavedObjectsClient.find).toHaveBeenCalledWith({
        type: 'query',
        page: 1,
        perPage: 50,
        sortField: 'titleKeyword',
        sortOrder: 'asc',
      });
      expect(response.savedQueries).toEqual([{ id: 'foo', attributes: savedQueryAttributes }]);
    });

    it('should return the total count along with the requested queries', async () => {
      const mockResponse: SavedObjectsFindResponse<SavedQueryAttributes> = {
        page: 0,
        per_page: 0,
        saved_objects: [
          { id: 'foo', type: 'query', score: 0, attributes: savedQueryAttributes, references: [] },
        ],
        total: 5,
      };
      mockSavedObjectsClient.find.mockResolvedValue(mockResponse);

      const response = await context.find();

      expect(response.total).toEqual(5);
    });

    it('should find and return saved queries with search text matching the title field', async () => {
      const mockResponse: SavedObjectsFindResponse<SavedQueryAttributes> = {
        page: 0,
        per_page: 0,
        saved_objects: [
          { id: 'foo', type: 'query', score: 0, attributes: savedQueryAttributes, references: [] },
        ],
        total: 5,
      };
      mockSavedObjectsClient.find.mockResolvedValue(mockResponse);

      const response = await context.find({ search: 'Foo < And > Bar' });

      expect(mockSavedObjectsClient.find).toHaveBeenCalledWith({
        type: 'query',
        page: 1,
        perPage: 50,
        filter: 'query.attributes.title:(*Foo AND \\And AND Bar*)',
        sortField: 'titleKeyword',
        sortOrder: 'asc',
      });
      expect(response.savedQueries).toEqual([{ id: 'foo', attributes: savedQueryAttributes }]);
    });

    it('should find and return parsed filters and timefilters items', async () => {
      const mockResponse: SavedObjectsFindResponse<SavedQueryAttributes> = {
        page: 0,
        per_page: 0,
        saved_objects: [
          {
            id: 'foo',
            type: 'query',
            score: 0,
            attributes: savedQueryAttributesWithFilters,
            references: savedQueryReferences,
          },
        ],
        total: 5,
      };
      mockSavedObjectsClient.find.mockResolvedValue(mockResponse);

      const response = await context.find({ search: 'bar' });

      expect(response.savedQueries).toEqual([
        { id: 'foo', attributes: savedQueryAttributesWithFilters },
      ]);
    });

    it('should return an array of saved queries', async () => {
      const mockResponse: SavedObjectsFindResponse<SavedQueryAttributes> = {
        page: 0,
        per_page: 0,
        saved_objects: [
          { id: 'foo', type: 'query', score: 0, attributes: savedQueryAttributes, references: [] },
        ],
        total: 5,
      };
      mockSavedObjectsClient.find.mockResolvedValue(mockResponse);

      const response = await context.find();

      expect(response.savedQueries).toEqual(
        expect.objectContaining([
          {
            attributes: {
              description: 'bar',
              query: { language: 'kuery', query: 'response:200' },
              filters: [],
              title: 'foo',
            },
            id: 'foo',
          },
        ])
      );
    });

    it('should accept perPage and page properties', async () => {
      const mockResponse: SavedObjectsFindResponse<SavedQueryAttributes> = {
        page: 0,
        per_page: 0,
        saved_objects: [
          { id: 'foo', type: 'query', score: 0, attributes: savedQueryAttributes, references: [] },
          {
            id: 'bar',
            type: 'query',
            score: 0,
            attributes: savedQueryAttributesBar,
            references: [],
          },
        ],
        total: 5,
      };
      mockSavedObjectsClient.find.mockResolvedValue(mockResponse);

      const response = await context.find({
        page: 1,
        perPage: 2,
      });

      expect(mockSavedObjectsClient.find).toHaveBeenCalledWith({
        page: 1,
        perPage: 2,
        sortField: 'titleKeyword',
        sortOrder: 'asc',
        type: 'query',
      });
      expect(response.savedQueries).toEqual(
        expect.objectContaining([
          {
            attributes: {
              description: 'bar',
              query: { language: 'kuery', query: 'response:200' },
              filters: [],
              title: 'foo',
            },
            id: 'foo',
          },
          {
            attributes: {
              description: 'baz',
              query: { language: 'kuery', query: 'response:200' },
              title: 'bar',
            },
            id: 'bar',
          },
        ])
      );
    });
  });

  describe('get', function () {
    it('should retrieve a saved query by id', async () => {
      mockSavedObjectsClient.resolve.mockResolvedValue({
        saved_object: {
          id: 'foo',
          type: 'query',
          attributes: savedQueryAttributes,
          references: [],
        },
        outcome: 'exactMatch',
      });

      const response = await context.get('foo');
      expect(response).toEqual({ id: 'foo', attributes: savedQueryAttributes });
    });

    it('should only return saved queries', async () => {
      mockSavedObjectsClient.resolve.mockResolvedValue({
        saved_object: {
          id: 'foo',
          type: 'query',
          attributes: savedQueryAttributes,
          references: [],
        },
        outcome: 'exactMatch',
      });

      await context.get('foo');
      expect(mockSavedObjectsClient.resolve).toHaveBeenCalledWith('query', 'foo');
    });

    it('should parse a json query', async () => {
      mockSavedObjectsClient.resolve.mockResolvedValue({
        saved_object: {
          id: 'food',
          type: 'query',
          attributes: {
            title: 'food',
            description: 'bar',
            query: {
              language: 'kuery',
              query: '{"x": "y"}',
            },
          },
          references: [],
        },
        outcome: 'exactMatch',
      });

      const response = await context.get('food');
      const query = response.attributes.query as Query;
      expect(query.query).toEqual({ x: 'y' });
    });

    it('should handle null string', async () => {
      mockSavedObjectsClient.resolve.mockResolvedValue({
        saved_object: {
          id: 'food',
          type: 'query',
          attributes: {
            title: 'food',
            description: 'bar',
            query: {
              language: 'kuery',
              query: 'null',
            },
          },
          references: [],
        },
        outcome: 'exactMatch',
      });

      const response = await context.get('food');
      const query = response.attributes.query as Query;
      expect(query.query).toEqual('null');
    });

    it('should handle null quoted string', async () => {
      mockSavedObjectsClient.resolve.mockResolvedValue({
        saved_object: {
          id: 'food',
          type: 'query',
          attributes: {
            title: 'food',
            description: 'bar',
            query: {
              language: 'kuery',
              query: '"null"',
            },
          },
          references: [],
        },
        outcome: 'exactMatch',
      });

      const response = await context.get('food');
      const query = response.attributes.query as Query;
      expect(query.query).toEqual('"null"');
    });

    it('should not lose quotes', async () => {
      mockSavedObjectsClient.resolve.mockResolvedValue({
        saved_object: {
          id: 'food',
          type: 'query',
          attributes: {
            title: 'food',
            description: 'bar',
            query: {
              language: 'kuery',
              query: '"Bob"',
            },
          },
          references: [],
        },
        outcome: 'exactMatch',
      });

      const response = await context.get('food');
      const query = response.attributes.query as Query;
      expect(query.query).toEqual('"Bob"');
    });

    it('should inject references', async () => {
      mockSavedObjectsClient.resolve.mockResolvedValue({
        saved_object: {
          id: 'food',
          type: 'query',
          attributes: savedQueryAttributesWithFilters,
          references: [
            {
              id: 'my-new-index',
              type: DATA_VIEW_SAVED_OBJECT_TYPE,
              name: 'my-index',
            },
          ],
        },
        outcome: 'exactMatch',
      });

      const response = await context.get('food');
      expect(response.attributes.filters?.[0].meta.index).toBe('my-new-index');
    });

    it('should throw if conflict', async () => {
      mockSavedObjectsClient.resolve.mockResolvedValue({
        saved_object: {
          id: 'foo',
          type: 'query',
          attributes: savedQueryAttributes,
          references: [],
        },
        outcome: 'conflict',
      });

      const result = context.get('food');
      await expect(result).rejects.toMatchInlineSnapshot(
        `[Error: Multiple saved queries found with ID: food (legacy URL alias conflict)]`
      );
    });
  });

  describe('delete', function () {
    it('should delete the saved query for the given ID', async () => {
      await context.delete('foo');
      expect(mockSavedObjectsClient.delete).toHaveBeenCalledWith('query', 'foo', { force: true });
    });
  });

  describe('count', function () {
    it('should return the total number of saved queries', async () => {
      mockSavedObjectsClient.find.mockResolvedValue({
        total: 1,
        page: 0,
        per_page: 0,
        saved_objects: [],
      });

      const response = await context.count();

      expect(mockSavedObjectsClient.find).toHaveBeenCalledWith({
        type: 'query',
        page: 0,
        perPage: 0,
      });
      expect(response).toEqual(1);
    });
  });
});
