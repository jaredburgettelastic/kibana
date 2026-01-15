/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { EntityType } from '../../../../common/search_strategy';
import type { FieldValue } from '@elastic/elasticsearch/lib/api/types';
import {
  buildRiskScoreBucket,
  getESQL,
  generateEUID,
  getEntityIdField,
} from './calculate_esql_risk_scores';
import type { RiskScoreBucket } from '../types';
import { RIEMANN_ZETA_S_VALUE, RIEMANN_ZETA_VALUE } from './constants';

describe('Calculate risk scores with ESQL', () => {
  describe('generateEUID', () => {
    it('generates EUID calculation for user entity type', () => {
      const euid = generateEUID(EntityType.user);
      expect(euid).toContain('EVAL user.entity.id = COALESCE(');
      expect(euid).toContain('user.entity.id,');
      expect(euid).toContain('user.id,');
      expect(euid).toContain('user.email,');
      expect(euid).toContain('user.name');
      expect(euid).toContain('user.domain');
      expect(euid).toContain('host.id');
      expect(euid).toContain('host.name');
    });

    it('generates EUID calculation for host entity type', () => {
      const euid = generateEUID(EntityType.host);
      expect(euid).toContain('EVAL host.entity.id = COALESCE(');
      expect(euid).toContain('host.entity.id,');
      expect(euid).toContain('host.id,');
      expect(euid).toContain('host.domain');
      expect(euid).toContain('host.name');
      expect(euid).toContain('host.hostname');
      expect(euid).toContain('host.mac');
    });

    it('generates EUID calculation for service entity type', () => {
      const euid = generateEUID(EntityType.service);
      expect(euid).toContain('EVAL service.entity.id = COALESCE(service.entity.id, service.name)');
    });

    it('returns empty string for generic entity type', () => {
      const euid = generateEUID(EntityType.generic);
      expect(euid).toBe('');
    });
  });

  describe('getEntityIdField', () => {
    it('returns user.entity.id for user entity type', () => {
      expect(getEntityIdField(EntityType.user)).toBe('user.entity.id');
    });

    it('returns host.entity.id for host entity type', () => {
      expect(getEntityIdField(EntityType.host)).toBe('host.entity.id');
    });

    it('returns service.entity.id for service entity type', () => {
      expect(getEntityIdField(EntityType.service)).toBe('service.entity.id');
    });

    it('returns entity.id for generic entity type', () => {
      expect(getEntityIdField(EntityType.generic)).toBe('entity.id');
    });
  });

  describe('ESQL query', () => {
    it('matches snapshot', () => {
      const q = getESQL(EntityType.host, { lower: 'abel', upper: 'zuzanna' }, 10000, 3500);
      expect(q).toMatchSnapshot();
    });

    it('includes EUID calculation for host entity type', () => {
      const q = getESQL(EntityType.host, { lower: 'abel', upper: 'zuzanna' }, 10000, 3500);
      expect(q).toContain('EVAL host.entity.id = COALESCE(');
      expect(q).toContain('BY host.entity.id');
    });

    it('includes EUID calculation for user entity type', () => {
      const q = getESQL(EntityType.user, { lower: 'abel', upper: 'zuzanna' }, 10000, 3500);
      expect(q).toContain('EVAL user.entity.id = COALESCE(');
      expect(q).toContain('BY user.entity.id');
    });
  });

  describe('buildRiskScoreBucket', () => {
    it('parses esql results into RiskScoreBucket', () => {
      const inputs = [
        '{ "risk_score": "50", "time": "2021-08-23T18:00:05.000Z", "rule_name": "Test rule 5", "id": "test_id_5" }',
        '{ "risk_score": "40", "time": "2021-08-22T18:00:04.000Z", "rule_name": "Test rule 4", "id": "test_id_4" }',
        '{ "risk_score": "30", "time": "2021-08-21T18:00:03.000Z", "rule_name": "Test rule 3", "id": "test_id_3" }',
        '{ "risk_score": "20", "time": "2021-08-20T18:00:02.000Z", "rule_name": "Test rule 2", "id": "test_id_2" }',
        '{ "risk_score": "10", "time": "2021-08-19T18:00:01.000Z", "rule_name": "Test rule 1", "id": "test_id_1" }',
      ];
      const alertCount = 10;
      const riskScore = 100;
      const entityValue = 'hostname';

      const esqlResultRow = [alertCount, riskScore, inputs, entityValue];

      const bucket = buildRiskScoreBucket(
        EntityType.host,
        '.alerts-security.alerts-default'
      )(esqlResultRow as FieldValue[]);

      const expected: RiskScoreBucket = {
        key: { 'host.entity.id': entityValue },
        doc_count: alertCount,
        top_inputs: {
          doc_count: inputs.length,
          risk_details: {
            value: {
              score: riskScore,
              normalized_score: riskScore / RIEMANN_ZETA_VALUE,
              notes: [],
              category_1_score: riskScore, // Don't normalize here - will be normalized in calculate_risk_scores.ts
              category_1_count: alertCount,
              risk_inputs: [
                {
                  index: '.alerts-security.alerts-default',
                  score: 50,
                  time: '2021-08-23T18:00:05.000Z',
                  rule_name: 'Test rule 5',
                  id: 'test_id_5',
                  contribution: 50 / 1 ** RIEMANN_ZETA_S_VALUE / RIEMANN_ZETA_VALUE,
                },
                {
                  index: '.alerts-security.alerts-default',
                  score: 40,
                  time: '2021-08-22T18:00:04.000Z',
                  rule_name: 'Test rule 4',
                  id: 'test_id_4',
                  contribution: 40 / 2 ** RIEMANN_ZETA_S_VALUE / RIEMANN_ZETA_VALUE,
                },
                {
                  index: '.alerts-security.alerts-default',
                  score: 30,
                  time: '2021-08-21T18:00:03.000Z',
                  rule_name: 'Test rule 3',
                  id: 'test_id_3',
                  contribution: 30 / 3 ** RIEMANN_ZETA_S_VALUE / RIEMANN_ZETA_VALUE,
                },
                {
                  index: '.alerts-security.alerts-default',
                  score: 20,
                  time: '2021-08-20T18:00:02.000Z',
                  rule_name: 'Test rule 2',
                  id: 'test_id_2',
                  contribution: 20 / 4 ** RIEMANN_ZETA_S_VALUE / RIEMANN_ZETA_VALUE,
                },
                {
                  index: '.alerts-security.alerts-default',
                  score: 10,
                  time: '2021-08-19T18:00:01.000Z',
                  rule_name: 'Test rule 1',
                  id: 'test_id_1',
                  contribution: 10 / 5 ** RIEMANN_ZETA_S_VALUE / RIEMANN_ZETA_VALUE,
                },
              ],
            },
          },
        },
      };

      expect(bucket).toEqual(expected);
    });

    /*  The below tests are a result of https://github.com/elastic/sdh-security-team/issues/1529 */

    describe('Rule name and category special characters', () => {
      it('decodes Base64 encoded rule_name and category', () => {
        // Simulate ESQL TO_BASE64 output
        const ruleNameWithQuotes = 'Test "Quoted" Alert';
        const categoryWithBackslash = 'signal\\test';
        const ruleNameB64 = Buffer.from(ruleNameWithQuotes, 'utf-8').toString('base64');
        const categoryB64 = Buffer.from(categoryWithBackslash, 'utf-8').toString('base64');

        const inputs = [
          `{ "risk_score": "75", "time": "2021-08-23T18:00:05.000Z", "index": ".alerts-security.alerts-default", "rule_name_b64": "${ruleNameB64}", "category_b64": "${categoryB64}", "id": "test_id_1" }`,
        ];
        const alertCount = 1;
        const riskScore = 75;
        const entityValue = 'hostname';

        const esqlResultRow = [alertCount, riskScore, inputs, entityValue];

        const bucket = buildRiskScoreBucket(
          EntityType.host,
          '.alerts-security.alerts-default'
        )(esqlResultRow as FieldValue[]);

        expect(bucket.top_inputs.risk_details.value.risk_inputs[0].rule_name).toBe(
          ruleNameWithQuotes
        );
        expect(bucket.top_inputs.risk_details.value.risk_inputs[0].category).toBe(
          categoryWithBackslash
        );
      });

      it('handles rule names with double quotes', () => {
        const ruleName = 'Alert: "Suspicious Activity" Detected';
        const ruleNameB64 = Buffer.from(ruleName, 'utf-8').toString('base64');

        const inputs = [
          `{ "risk_score": "80", "time": "2021-08-23T18:00:05.000Z", "index": ".alerts-security.alerts-default", "rule_name_b64": "${ruleNameB64}", "category_b64": "c2lnbmFs", "id": "test_id_1" }`,
        ];

        const esqlResultRow = [1, 80, inputs, 'hostname'];
        const bucket = buildRiskScoreBucket(
          EntityType.host,
          '.alerts-security.alerts-default'
        )(esqlResultRow as FieldValue[]);

        expect(bucket.top_inputs.risk_details.value.risk_inputs[0].rule_name).toBe(ruleName);
      });

      it('handles rule names with backslashes', () => {
        const ruleName = 'C:\\Windows\\System32\\malware.exe';
        const ruleNameB64 = Buffer.from(ruleName, 'utf-8').toString('base64');

        const inputs = [
          `{ "risk_score": "90", "time": "2021-08-23T18:00:05.000Z", "index": ".alerts-security.alerts-default", "rule_name_b64": "${ruleNameB64}", "category_b64": "c2lnbmFs", "id": "test_id_1" }`,
        ];

        const esqlResultRow = [1, 90, inputs, 'hostname'];
        const bucket = buildRiskScoreBucket(
          EntityType.host,
          '.alerts-security.alerts-default'
        )(esqlResultRow as FieldValue[]);

        expect(bucket.top_inputs.risk_details.value.risk_inputs[0].rule_name).toBe(ruleName);
      });

      it('handles rule names with newlines and tabs', () => {
        const ruleName = 'Multi\nLine\tRule';
        const ruleNameB64 = Buffer.from(ruleName, 'utf-8').toString('base64');

        const inputs = [
          `{ "risk_score": "85", "time": "2021-08-23T18:00:05.000Z", "index": ".alerts-security.alerts-default", "rule_name_b64": "${ruleNameB64}", "category_b64": "c2lnbmFs", "id": "test_id_1" }`,
        ];

        const esqlResultRow = [1, 85, inputs, 'hostname'];
        const bucket = buildRiskScoreBucket(
          EntityType.host,
          '.alerts-security.alerts-default'
        )(esqlResultRow as FieldValue[]);

        expect(bucket.top_inputs.risk_details.value.risk_inputs[0].rule_name).toBe(ruleName);
      });

      it('handles rule names with mixed special characters', () => {
        const ruleName = 'Alert: "Path\\To\\File"\nWith Newline\tAnd Tab';
        const category = 'Category with "quotes" and \\backslashes\\';
        const ruleNameB64 = Buffer.from(ruleName, 'utf-8').toString('base64');
        const categoryB64 = Buffer.from(category, 'utf-8').toString('base64');

        const inputs = [
          `{ "risk_score": "95", "time": "2021-08-23T18:00:05.000Z", "index": ".alerts-security.alerts-default", "rule_name_b64": "${ruleNameB64}", "category_b64": "${categoryB64}", "id": "test_id_1" }`,
        ];

        const esqlResultRow = [1, 95, inputs, 'hostname'];
        const bucket = buildRiskScoreBucket(
          EntityType.host,
          '.alerts-security.alerts-default'
        )(esqlResultRow as FieldValue[]);

        expect(bucket.top_inputs.risk_details.value.risk_inputs[0].rule_name).toBe(ruleName);
        expect(bucket.top_inputs.risk_details.value.risk_inputs[0].category).toBe(category);
      });

      it('handles Unicode characters', () => {
        const ruleName = 'Alert: 你好世界 🔥 Émojis';
        const ruleNameB64 = Buffer.from(ruleName, 'utf-8').toString('base64');

        const inputs = [
          `{ "risk_score": "70", "time": "2021-08-23T18:00:05.000Z", "index": ".alerts-security.alerts-default", "rule_name_b64": "${ruleNameB64}", "category_b64": "c2lnbmFs", "id": "test_id_1" }`,
        ];

        const esqlResultRow = [1, 70, inputs, 'hostname'];
        const bucket = buildRiskScoreBucket(
          EntityType.host,
          '.alerts-security.alerts-default'
        )(esqlResultRow as FieldValue[]);

        expect(bucket.top_inputs.risk_details.value.risk_inputs[0].rule_name).toBe(ruleName);
      });
    });

    describe('Backward compatibility', () => {
      it('handles old format without Base64 encoding (rule_name without _b64 suffix)', () => {
        const inputs = [
          '{ "risk_score": "50", "time": "2021-08-23T18:00:05.000Z", "index": ".alerts-security.alerts-default", "rule_name": "Old Format Rule", "category": "signal", "id": "test_id_1" }',
        ];
        const alertCount = 1;
        const riskScore = 50;
        const entityValue = 'hostname';

        const esqlResultRow = [alertCount, riskScore, inputs, entityValue];

        const bucket = buildRiskScoreBucket(
          EntityType.host,
          '.alerts-security.alerts-default'
        )(esqlResultRow as FieldValue[]);

        expect(bucket.top_inputs.risk_details.value.risk_inputs[0].rule_name).toBe(
          'Old Format Rule'
        );
        expect(bucket.top_inputs.risk_details.value.risk_inputs[0].category).toBe('signal');
      });

      it('prefers Base64 encoded fields over plain fields when both exist', () => {
        const correctRuleName = 'Rule Name like this would make life so much easier';
        const ruleNameB64 = Buffer.from(correctRuleName, 'utf-8').toString('base64');

        const inputs = [
          `{ "risk_score": "60", "time": "2021-08-23T18:00:05.000Z", "index": ".alerts-security.alerts-default", "rule_name": "Wrong Name", "rule_name_b64": "${ruleNameB64}", "category": "wrong", "category_b64": "Y29ycmVjdA==", "id": "test_id_1" }`,
        ];

        const esqlResultRow = [1, 60, inputs, 'hostname'];
        const bucket = buildRiskScoreBucket(
          EntityType.host,
          '.alerts-security.alerts-default'
        )(esqlResultRow as FieldValue[]);

        expect(bucket.top_inputs.risk_details.value.risk_inputs[0].rule_name).toBe(correctRuleName);
        expect(bucket.top_inputs.risk_details.value.risk_inputs[0].category).toBe('correct');
      });
    });

    describe('Multiple inputs with mixed formats', () => {
      it('handles array of inputs with both Base64 and plain text', () => {
        const ruleNameB64 = Buffer.from('Test "Quoted" Alert', 'utf-8').toString('base64');
        const inputs = [
          `{ "risk_score": "75", "time": "2021-08-23T18:00:05.000Z", "index": ".alerts-security.alerts-default", "rule_name_b64": "${ruleNameB64}", "category_b64": "c2lnbmFs", "id": "test_id_1" }`,
          '{ "risk_score": "50", "time": "2021-08-22T18:00:04.000Z", "index": ".alerts-security.alerts-default", "rule_name": "Plain Rule", "category": "signal", "id": "test_id_2" }',
        ];

        const esqlResultRow = [2, 125, inputs, 'hostname'];
        const bucket = buildRiskScoreBucket(
          EntityType.host,
          '.alerts-security.alerts-default'
        )(esqlResultRow as FieldValue[]);

        expect(bucket.top_inputs.risk_details.value.risk_inputs).toHaveLength(2);
        expect(bucket.top_inputs.risk_details.value.risk_inputs[0].rule_name).toBe(
          'Test "Quoted" Alert'
        );
        expect(bucket.top_inputs.risk_details.value.risk_inputs[1].rule_name).toBe('Plain Rule');
      });
    });
  });
});
