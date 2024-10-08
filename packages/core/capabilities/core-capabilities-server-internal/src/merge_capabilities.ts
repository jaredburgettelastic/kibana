/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import { mergeWith } from 'lodash';
import type { Capabilities } from '@kbn/core-capabilities-common';

export const mergeCapabilities = (...sources: Array<Partial<Capabilities>>): Capabilities =>
  mergeWith({}, ...sources, (a: unknown, b: unknown) => {
    if (
      (typeof a === 'boolean' && typeof b === 'object') ||
      (typeof a === 'object' && typeof b === 'boolean')
    ) {
      throw new Error(`conflict trying to merge boolean with object`);
    }

    if (typeof a === 'boolean' && typeof b === 'boolean' && a !== b) {
      throw new Error(`conflict trying to merge booleans with different values`);
    }
  });
