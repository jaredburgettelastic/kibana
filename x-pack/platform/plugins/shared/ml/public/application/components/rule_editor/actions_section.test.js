/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import React from 'react';
import { renderWithI18n } from '@kbn/test-jest-helpers';
import { ML_DETECTOR_RULE_ACTION } from '@kbn/ml-anomaly-utils';

import { ActionsSection } from './actions_section';

describe('ActionsSection', () => {
  const onSkipResultChange = jest.fn();
  const onSkipModelUpdateChange = jest.fn();

  const requiredProps = {
    onSkipResultChange,
    onSkipModelUpdateChange,
  };

  test('renders with no actions selected', () => {
    const props = {
      ...requiredProps,
      actions: [],
    };

    const { container } = renderWithI18n(<ActionsSection {...props} />);

    expect(container).toMatchSnapshot();
  });

  test('renders with skip_result selected', () => {
    const props = {
      ...requiredProps,
      actions: [ML_DETECTOR_RULE_ACTION.SKIP_RESULT],
    };

    const { container } = renderWithI18n(<ActionsSection {...props} />);

    expect(container).toMatchSnapshot();
  });

  test('renders with skip_result and skip_model_update selected', () => {
    const { container } = renderWithI18n(
      <ActionsSection
        actions={[ML_DETECTOR_RULE_ACTION.SKIP_RESULT, ML_DETECTOR_RULE_ACTION.SKIP_MODEL_UPDATE]}
        onSkipResultChange={() => {}}
        onSkipModelUpdateChange={() => {}}
      />
    );

    expect(container).toMatchSnapshot();
  });
});
