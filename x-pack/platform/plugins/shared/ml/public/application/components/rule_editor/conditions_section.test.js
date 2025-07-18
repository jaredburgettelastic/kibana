/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

// Mock the mlJobService that is imported for saving rules.
jest.mock('../../services/job_service', () => 'mlJobService');

import React from 'react';
import { renderWithI18n } from '@kbn/test-jest-helpers';

import { ML_DETECTOR_RULE_APPLIES_TO, ML_DETECTOR_RULE_OPERATOR } from '@kbn/ml-anomaly-utils';

import { ConditionsSection } from './conditions_section';
import { getNewConditionDefaults } from './utils';

describe('ConditionsSectionExpression', () => {
  const addCondition = jest.fn();
  const updateCondition = jest.fn();
  const deleteCondition = jest.fn();

  const testCondition = {
    applies_to: ML_DETECTOR_RULE_APPLIES_TO.TYPICAL,
    operator: ML_DETECTOR_RULE_OPERATOR.GREATER_THAN_OR_EQUAL,
    value: 1.23,
  };

  const requiredProps = {
    addCondition,
    updateCondition,
    deleteCondition,
  };

  test(`don't render when the section is not enabled`, () => {
    const props = {
      ...requiredProps,
      isEnabled: false,
    };

    const { container } = renderWithI18n(<ConditionsSection {...props} />);

    expect(container).toMatchSnapshot();
  });

  test('renders when enabled with no conditions supplied', () => {
    const props = {
      ...requiredProps,
      isEnabled: true,
    };

    const { container } = renderWithI18n(<ConditionsSection {...props} />);

    expect(container).toMatchSnapshot();
  });

  test('renders when enabled with empty conditions supplied', () => {
    const props = {
      ...requiredProps,
      isEnabled: true,
      conditions: [],
    };

    const { container } = renderWithI18n(<ConditionsSection {...props} />);

    expect(container).toMatchSnapshot();
  });

  test('renders when enabled with one condition', () => {
    const props = {
      ...requiredProps,
      isEnabled: true,
      conditions: [getNewConditionDefaults()],
    };

    const { container } = renderWithI18n(<ConditionsSection {...props} />);

    expect(container).toMatchSnapshot();
  });

  test('renders when enabled with two conditions', () => {
    const props = {
      ...requiredProps,
      isEnabled: true,
      conditions: [getNewConditionDefaults(), testCondition],
    };

    const { container } = renderWithI18n(<ConditionsSection {...props} />);

    expect(container).toMatchSnapshot();
  });

  test(`don't render when not enabled with conditions`, () => {
    const props = {
      ...requiredProps,
      isEnabled: false,
      conditions: [getNewConditionDefaults(), testCondition],
    };

    const { container } = renderWithI18n(<ConditionsSection {...props} />);

    expect(container).toMatchSnapshot();
  });
});
