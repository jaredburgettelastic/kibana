/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { isRiskScoreCalculationComplete } from './helpers';

const emptyResult = {
  after_keys: {},
  errors: [],
  scores_written: 0,
};

describe('isRiskScoreCalculationComplete', () => {
  it('is true if both after_keys.host and after_keys.user are empty', () => {
    const result = {
      ...emptyResult,
      after_keys: {
        host: {},
        user: {},
      },
    };
    expect(isRiskScoreCalculationComplete(result)).toEqual(true);
  });

  it('is true if after_keys is an empty object', () => {
    const result = {
      ...emptyResult,
      after_keys: {},
    };
    expect(isRiskScoreCalculationComplete(result)).toEqual(true);
  });

  it('is false if the host key has a key/value', () => {
    const result = {
      ...emptyResult,
      after_keys: {
        host: {
          key: 'value',
        },
      },
    };
    expect(isRiskScoreCalculationComplete(result)).toEqual(false);
  });

  it('is false if the user key has a key/value', () => {
    const result = {
      ...emptyResult,
      after_keys: {
        user: {
          key: 'value',
        },
      },
    };
    expect(isRiskScoreCalculationComplete(result)).toEqual(false);
  });
});
