/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import { sortBy } from 'lodash';
import { MAIN_SAVED_OBJECT_INDEX } from '@kbn/core-saved-objects-server';
import expect from '@kbn/expect';
import { SavedObject } from '@kbn/core/server';
import { X_ELASTIC_INTERNAL_ORIGIN_REQUEST } from '@kbn/core-http-common';
import { FtrProviderContext } from '../../ftr_provider_context';

export default function ({ getService }: FtrProviderContext) {
  const supertest = getService('supertest');
  const kibanaServer = getService('kibanaServer');
  const es = getService('es');
  const SPACE_ID = 'ftr-so-find';
  const UUID_PATTERN = new RegExp(
    /^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/i
  );

  describe('find', () => {
    before(async () => {
      await kibanaServer.spaces.create({ id: SPACE_ID, name: SPACE_ID });
      await kibanaServer.importExport.load(
        'src/platform/test/api_integration/fixtures/kbn_archiver/saved_objects/basic.json',
        { space: SPACE_ID }
      );

      await kibanaServer.spaces.create({ id: `${SPACE_ID}-foo`, name: `${SPACE_ID}-foo` });
      await kibanaServer.importExport.load(
        'src/platform/test/api_integration/fixtures/kbn_archiver/saved_objects/basic.json',
        {
          space: `${SPACE_ID}-foo`,
        }
      );
    });

    after(async () => {
      await kibanaServer.spaces.delete(SPACE_ID);
      await kibanaServer.spaces.delete(`${SPACE_ID}-foo`);
    });

    it('should return 200 with individual responses', async () =>
      await supertest
        .get(`/s/${SPACE_ID}/api/saved_objects/_find?type=visualization&fields=title`)
        .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
        .expect(200)
        .then((resp) => {
          expect(resp.body.saved_objects.map((so: { id: string }) => so.id)).to.eql([
            'dd7caf20-9efd-11e7-acb3-3dab96693fab',
          ]);
          expect(resp.body.saved_objects[0].migrationVersion).to.be.ok();
          expect(resp.body.saved_objects[0].typeMigrationVersion).to.be.ok();
        }));

    it('should migrate saved object before returning', async () => {
      await es.update({
        index: MAIN_SAVED_OBJECT_INDEX,
        id: `${SPACE_ID}:config:7.0.0-alpha1`,
        doc: {
          coreMigrationVersion: '7.0.0',
          typeMigrationVersion: '7.0.0',
        },
      });

      const { body } = await supertest
        .get(`/s/${SPACE_ID}/api/saved_objects/_find?type=config`)
        .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
        .expect(200);

      expect(body.saved_objects.map((so: { id: string }) => so.id)).to.eql(['7.0.0-alpha1']);
      expect(body.saved_objects[0].coreMigrationVersion).to.be.ok();
      expect(body.saved_objects[0].coreMigrationVersion).not.to.be('7.0.0');
      expect(body.saved_objects[0].typeMigrationVersion).to.be.ok();
      expect(body.saved_objects[0].typeMigrationVersion).not.to.be('7.0.0');
    });

    describe('unknown type', () => {
      it('should return 200 with empty response', async () =>
        await supertest
          .get(`/s/${SPACE_ID}/api/saved_objects/_find?type=wigwags`)
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(200)
          .then((resp) => {
            expect(resp.body).to.eql({
              page: 1,
              per_page: 20,
              total: 0,
              saved_objects: [],
            });
          }));
    });

    // FLAKY: https://github.com/elastic/kibana/issues/85911
    describe.skip('page beyond total', () => {
      it('should return 200 with empty response', async () =>
        await supertest
          .get(`/s/${SPACE_ID}/api/saved_objects/_find?type=visualization&page=100&per_page=100`)
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(200)
          .then((resp) => {
            expect(resp.body).to.eql({
              page: 100,
              per_page: 100,
              total: 1,
              saved_objects: [],
            });
          }));
    });

    describe('unknown search field', () => {
      it('should return 200 with empty response', async () =>
        await supertest
          .get(`/s/${SPACE_ID}/api/saved_objects/_find?type=url&search_fields=a`)
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(200)
          .then((resp) => {
            expect(resp.body).to.eql({
              page: 1,
              per_page: 20,
              total: 0,
              saved_objects: [],
            });
          }));
    });

    describe('unknown namespace', () => {
      it('should return 200 with empty response', async () =>
        await supertest
          .get(`/s/${SPACE_ID}/api/saved_objects/_find?type=visualization&namespaces=foo`)
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(200)
          .then((resp) => {
            expect(resp.body).to.eql({
              page: 1,
              per_page: 20,
              total: 0,
              saved_objects: [],
            });
          }));
    });

    describe('known namespace', () => {
      it('should return 200 with individual responses', async () =>
        await supertest
          .get(`/api/saved_objects/_find?type=visualization&fields=title&namespaces=${SPACE_ID}`)
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(200)
          .then((resp) => {
            expect(
              resp.body.saved_objects.map((so: { id: string; namespaces: string[] }) => ({
                id: so.id,
                namespaces: so.namespaces,
              }))
            ).to.eql([{ id: 'dd7caf20-9efd-11e7-acb3-3dab96693fab', namespaces: [SPACE_ID] }]);
            expect(resp.body.saved_objects[0].migrationVersion).to.be.ok();
            expect(resp.body.saved_objects[0].typeMigrationVersion).to.be.ok();
          }));
    });

    describe('wildcard namespace', () => {
      it('should return 200 with individual responses from the all namespaces', async () =>
        await supertest
          .get(
            `/api/saved_objects/_find?type=visualization&fields=title&fields=originId&namespaces=*`
          )
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(200)
          .then((resp) => {
            const knownDocuments = resp.body.saved_objects.filter((so: { namespaces: string[] }) =>
              so.namespaces.some((ns) => [SPACE_ID, `${SPACE_ID}-foo`].includes(ns))
            );

            const [obj1, obj2] = sortBy(knownDocuments, 'namespaces').map(
              ({ id, originId, namespaces }: SavedObject) => ({ id, originId, namespaces })
            );

            expect(obj1.id).to.equal('dd7caf20-9efd-11e7-acb3-3dab96693fab');
            expect(obj1.originId).to.equal(undefined);
            expect(obj1.namespaces).to.eql([SPACE_ID]);

            expect(obj2.id).to.match(UUID_PATTERN); // this was imported to the second space and hit an unresolvable conflict, so the object ID was regenerated silently
            expect(obj2.originId).to.equal('dd7caf20-9efd-11e7-acb3-3dab96693fab');
            expect(obj2.namespaces).to.eql([`${SPACE_ID}-foo`]);
          }));
    });

    describe('with a filter', () => {
      it('should return 200 with a valid response', async () =>
        await supertest
          .get(
            `/s/${SPACE_ID}/api/saved_objects/_find?type=visualization&filter=visualization.attributes.title:"Count of requests"`
          )
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(200)
          .then((resp) => {
            expect(resp.body.saved_objects.map((so: { id: string }) => so.id)).to.eql([
              'dd7caf20-9efd-11e7-acb3-3dab96693fab',
            ]);
          }));

      it('wrong type should return 400 with Bad Request', async () =>
        await supertest
          .get(
            `/s/${SPACE_ID}/api/saved_objects/_find?type=visualization&filter=dashboard.attributes.title:foo`
          )
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(400)
          .then((resp) => {
            expect(resp.body).to.eql({
              error: 'Bad Request',
              message: 'This type dashboard is not allowed: Bad Request',
              statusCode: 400,
            });
          }));

      it('KQL syntax error should return 400 with Bad Request', async () =>
        await supertest
          .get(
            `/s/${SPACE_ID}/api/saved_objects/_find?type=dashboard&filter=dashboard.attributes.title:foo<invalid`
          )
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(400)
          .then((resp) => {
            expect(resp.body.error).to.be('Bad Request');
            expect(resp.body.statusCode).to.be(400);
            expect(resp.body.message).to.match(/KQLSyntaxError[\s\S]+Bad Request/);
          }));
    });

    describe('using aggregations', () => {
      it('should return 200 with valid response for a valid aggregation', async () =>
        await supertest
          .get(
            `/s/${SPACE_ID}/api/saved_objects/_find?type=visualization&per_page=0&aggs=${encodeURIComponent(
              JSON.stringify({
                type_count: { max: { field: 'visualization.attributes.version' } },
              })
            )}`
          )
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(200)
          .then((resp) => {
            expect(resp.body).to.eql({
              aggregations: {
                type_count: {
                  value: 1,
                },
              },
              page: 1,
              per_page: 0,
              saved_objects: [],
              total: 1,
            });
          }));

      it('should return a 400 when referencing an invalid SO attribute', async () =>
        await supertest
          .get(
            `/s/${SPACE_ID}/api/saved_objects/_find?type=visualization&per_page=0&aggs=${encodeURIComponent(
              JSON.stringify({
                type_count: { max: { field: 'dashboard.attributes.version' } },
              })
            )}`
          )
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(400)
          .then((resp) => {
            expect(resp.body).to.eql({
              error: 'Bad Request',
              message:
                'Invalid aggregation: [type_count.max.field] Invalid attribute path: dashboard.attributes.version: Bad Request',
              statusCode: 400,
            });
          }));

      it('should return a 400 when using a forbidden aggregation option', async () =>
        await supertest
          .get(
            `/s/${SPACE_ID}/api/saved_objects/_find?type=visualization&per_page=0&aggs=${encodeURIComponent(
              JSON.stringify({
                type_count: {
                  max: {
                    field: 'visualization.attributes.version',
                    script: 'Bad script is bad',
                  },
                },
              })
            )}`
          )
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(400)
          .then((resp) => {
            expect(resp.body).to.eql({
              error: 'Bad Request',
              message:
                'Invalid aggregation: [type_count.max.script]: definition for this key is missing: Bad Request',
              statusCode: 400,
            });
          }));
    });

    describe('`has_reference` and `has_reference_operator` parameters', () => {
      before(async () => {
        await kibanaServer.importExport.load(
          'src/platform/test/api_integration/fixtures/kbn_archiver/saved_objects/references.json',
          { space: SPACE_ID }
        );
      });
      after(async () => {
        await kibanaServer.importExport.unload(
          'src/platform/test/api_integration/fixtures/kbn_archiver/saved_objects/references.json',
          { space: SPACE_ID }
        );
      });

      it('search for a reference', async () => {
        await supertest
          .get(`/s/${SPACE_ID}/api/saved_objects/_find`)
          .query({
            type: 'visualization',
            has_reference: JSON.stringify({ type: 'ref-type', id: 'ref-1' }),
          })
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(200)
          .then((resp) => {
            const objects = resp.body.saved_objects;
            expect(objects.map((obj: SavedObject) => obj.id)).to.eql([
              'only-ref-1',
              'ref-1-and-ref-2',
            ]);
          });
      });

      it('search for multiple references with OR operator', async () => {
        await supertest
          .get(`/s/${SPACE_ID}/api/saved_objects/_find`)
          .query({
            type: 'visualization',
            has_reference: JSON.stringify([
              { type: 'ref-type', id: 'ref-1' },
              { type: 'ref-type', id: 'ref-2' },
            ]),
            has_reference_operator: 'OR',
          })
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(200)
          .then((resp) => {
            const objects = resp.body.saved_objects;
            expect(objects.map((obj: SavedObject) => obj.id)).to.eql([
              'only-ref-1',
              'only-ref-2',
              'ref-1-and-ref-2',
            ]);
          });
      });

      it('search for multiple references with AND operator', async () => {
        await supertest
          .get(`/s/${SPACE_ID}/api/saved_objects/_find`)
          .query({
            type: 'visualization',
            has_reference: JSON.stringify([
              { type: 'ref-type', id: 'ref-1' },
              { type: 'ref-type', id: 'ref-2' },
            ]),
            has_reference_operator: 'AND',
          })
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(200)
          .then((resp) => {
            const objects = resp.body.saved_objects;
            expect(objects.map((obj: SavedObject) => obj.id)).to.eql(['ref-1-and-ref-2']);
          });
      });
    });

    describe('`has_no_reference` and `has_no_reference_operator` parameters', () => {
      before(async () => {
        await kibanaServer.importExport.load(
          'src/platform/test/api_integration/fixtures/kbn_archiver/saved_objects/references.json',
          { space: SPACE_ID }
        );
      });
      after(async () => {
        await kibanaServer.importExport.unload(
          'src/platform/test/api_integration/fixtures/kbn_archiver/saved_objects/references.json',
          { space: SPACE_ID }
        );
      });

      it('search for objects not containing a reference', async () => {
        await supertest
          .get(`/s/${SPACE_ID}/api/saved_objects/_find`)
          .query({
            type: 'visualization',
            has_no_reference: JSON.stringify({ type: 'ref-type', id: 'ref-1' }),
          })
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(200)
          .then((resp) => {
            const objects = resp.body.saved_objects;
            const ids = objects.map((obj: SavedObject) => obj.id);
            expect(ids).to.contain('only-ref-2');
            expect(ids).to.contain('only-ref-3');
            expect(ids).not.to.contain('only-ref-1');
            expect(ids).not.to.contain('ref-1-and-ref-2');
          });
      });

      it('search for multiple references with OR operator', async () => {
        await supertest
          .get(`/s/${SPACE_ID}/api/saved_objects/_find`)
          .query({
            type: 'visualization',
            has_no_reference: JSON.stringify([
              { type: 'ref-type', id: 'ref-1' },
              { type: 'ref-type', id: 'ref-2' },
            ]),
            has_no_reference_operator: 'OR',
          })
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(200)
          .then((resp) => {
            const objects = resp.body.saved_objects;
            const ids = objects.map((obj: SavedObject) => obj.id);

            expect(ids).to.contain('only-ref-3');
            expect(ids).not.to.contain('only-ref-1');
            expect(ids).not.to.contain('only-ref-2');
            expect(ids).not.to.contain('ref-1-and-ref-2');
          });
      });

      it('search for multiple references with AND operator', async () => {
        await supertest
          .get(`/s/${SPACE_ID}/api/saved_objects/_find`)
          .query({
            type: 'visualization',
            has_no_reference: JSON.stringify([
              { type: 'ref-type', id: 'ref-1' },
              { type: 'ref-type', id: 'ref-2' },
            ]),
            has_no_reference_operator: 'AND',
          })
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(200)
          .then((resp) => {
            const objects = resp.body.saved_objects;
            const ids = objects.map((obj: SavedObject) => obj.id);
            expect(ids).to.contain('only-ref-1');
            expect(ids).to.contain('only-ref-2');
            expect(ids).to.contain('only-ref-3');
            expect(ids).not.to.contain('ref-1-and-ref-2');
          });
      });
    });

    describe('with both `has_reference` and `has_no_reference` parameters', () => {
      before(async () => {
        await kibanaServer.importExport.load(
          'src/platform/test/api_integration/fixtures/kbn_archiver/saved_objects/references.json',
          { space: SPACE_ID }
        );
      });
      after(async () => {
        await kibanaServer.importExport.unload(
          'src/platform/test/api_integration/fixtures/kbn_archiver/saved_objects/references.json',
          { space: SPACE_ID }
        );
      });

      it('search for objects containing a reference and excluding another reference', async () => {
        await supertest
          .get(`/s/${SPACE_ID}/api/saved_objects/_find`)
          .query({
            type: 'visualization',
            has_reference: JSON.stringify({ type: 'ref-type', id: 'ref-1' }),
            has_no_reference: JSON.stringify({ type: 'ref-type', id: 'ref-2' }),
          })
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(200)
          .then((resp) => {
            const objects = resp.body.saved_objects;
            const ids = objects.map((obj: SavedObject) => obj.id);
            expect(ids).to.eql(['only-ref-1']);
          });
      });

      it('search for objects with same reference passed to `has_reference` and `has_no_reference`', async () => {
        await supertest
          .get(`/s/${SPACE_ID}/api/saved_objects/_find`)
          .query({
            type: 'visualization',
            has_reference: JSON.stringify({ type: 'ref-type', id: 'ref-1' }),
            has_no_reference: JSON.stringify({ type: 'ref-type', id: 'ref-1' }),
          })
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(200)
          .then((resp) => {
            const objects = resp.body.saved_objects;
            const ids = objects.map((obj: SavedObject) => obj.id);
            expect(ids).to.eql([]);
          });
      });
    });

    describe('searching for special characters', () => {
      before(async () => {
        await kibanaServer.importExport.load(
          'src/platform/test/api_integration/fixtures/kbn_archiver/saved_objects/find_edgecases.json',
          { space: SPACE_ID }
        );
      });
      after(async () => {
        await kibanaServer.importExport.unload(
          'src/platform/test/api_integration/fixtures/kbn_archiver/saved_objects/find_edgecases.json',
          { space: SPACE_ID }
        );
      });

      it('can search for objects with dashes', async () =>
        await supertest
          .get(`/s/${SPACE_ID}/api/saved_objects/_find`)
          .query({
            type: 'visualization',
            search_fields: 'title',
            search: 'my-vis*',
          })
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(200)
          .then((resp) => {
            const savedObjects = resp.body.saved_objects;
            expect(
              savedObjects.map((so: SavedObject<{ title: string }>) => so.attributes.title)
            ).to.eql(['my-visualization']);
          }));

      it('can search with the prefix search character just after a special one', async () =>
        await supertest
          .get(`/s/${SPACE_ID}/api/saved_objects/_find`)
          .query({
            type: 'visualization',
            search_fields: 'title',
            search: 'my-*',
          })
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(200)
          .then((resp) => {
            const savedObjects = resp.body.saved_objects;
            expect(
              savedObjects.map((so: SavedObject<{ title: string }>) => so.attributes.title)
            ).to.eql(['my-visualization']);
          }));

      it('can search for objects with asterisk', async () =>
        await supertest
          .get(`/s/${SPACE_ID}/api/saved_objects/_find`)
          .query({
            type: 'visualization',
            search_fields: 'title',
            search: 'some*vi*',
          })
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(200)
          .then((resp) => {
            const savedObjects = resp.body.saved_objects;
            expect(
              savedObjects.map((so: SavedObject<{ title: string }>) => so.attributes.title)
            ).to.eql(['some*visualization']);
          }));

      it('can still search tokens by prefix', async () =>
        await supertest
          .get(`/s/${SPACE_ID}/api/saved_objects/_find`)
          .query({
            type: 'visualization',
            search_fields: 'title',
            search: 'visuali*',
          })
          .set(X_ELASTIC_INTERNAL_ORIGIN_REQUEST, 'kibana')
          .expect(200)
          .then((resp) => {
            const savedObjects = resp.body.saved_objects;
            expect(
              savedObjects.map((so: SavedObject<{ title: string }>) => so.attributes.title)
            ).to.eql(['some*visualization', 'my-visualization']);
          }));
    });
  });
}
