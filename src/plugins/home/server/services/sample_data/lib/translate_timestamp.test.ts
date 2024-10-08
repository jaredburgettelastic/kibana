/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import { translateTimeRelativeToWeek } from './translate_timestamp';

describe('translateTimeRelativeToWeek', () => {
  const sourceReference = '2018-01-02T00:00:00'; // Tuesday
  const targetReference = '2018-04-25T18:24:58.650'; // Wednesday

  describe('2 weeks before', () => {
    test('should properly adjust timestamp when day is before targetReference day of week', () => {
      const source = '2017-12-18T23:50:00'; // Monday, -2 week relative to sourceReference
      const timestamp = translateTimeRelativeToWeek(source, sourceReference, targetReference);
      expect(timestamp).toBe('2018-04-09T23:50:00'); // Monday 2 week before targetReference week
    });

    test('should properly adjust timestamp when day is same as targetReference day of week', () => {
      const source = '2017-12-20T23:50:00'; // Wednesday, -2 week relative to sourceReference
      const timestamp = translateTimeRelativeToWeek(source, sourceReference, targetReference);
      expect(timestamp).toBe('2018-04-11T23:50:00'); // Wednesday 2 week before targetReference week
    });

    test('should properly adjust timestamp when day is after targetReference day of week', () => {
      const source = '2017-12-22T16:16:50'; // Friday, -2 week relative to sourceReference
      const timestamp = translateTimeRelativeToWeek(source, sourceReference, targetReference);
      expect(timestamp).toBe('2018-04-13T16:16:50'); // Friday 2 week before targetReference week
    });
  });

  describe('week before', () => {
    test('should properly adjust timestamp when day is before targetReference day of week', () => {
      const source = '2017-12-25T23:50:00'; // Monday, -1 week relative to sourceReference
      const timestamp = translateTimeRelativeToWeek(source, sourceReference, targetReference);
      expect(timestamp).toBe('2018-04-16T23:50:00'); // Monday 1 week before targetReference week
    });

    test('should properly adjust timestamp when day is same as targetReference day of week', () => {
      const source = '2017-12-27T23:50:00'; // Wednesday, -1 week relative to sourceReference
      const timestamp = translateTimeRelativeToWeek(source, sourceReference, targetReference);
      expect(timestamp).toBe('2018-04-18T23:50:00'); // Wednesday 1 week before targetReference week
    });

    test('should properly adjust timestamp when day is after targetReference day of week', () => {
      const source = '2017-12-29T16:16:50'; // Friday, -1 week relative to sourceReference
      const timestamp = translateTimeRelativeToWeek(source, sourceReference, targetReference);
      expect(timestamp).toBe('2018-04-20T16:16:50'); // Friday 1 week before targetReference week
    });
  });

  describe('same week', () => {
    test('should properly adjust timestamp when day is before targetReference day of week', () => {
      const source = '2018-01-01T23:50:00'; // Monday, same week relative to sourceReference
      const timestamp = translateTimeRelativeToWeek(source, sourceReference, targetReference);
      expect(timestamp).toBe('2018-04-23T23:50:00'); // Monday same week as targetReference
    });

    test('should properly adjust timestamp when day is same as targetReference day of week', () => {
      const source = '2018-01-03T23:50:00'; // Wednesday, same week relative to sourceReference
      const timestamp = translateTimeRelativeToWeek(source, sourceReference, targetReference);
      expect(timestamp).toBe('2018-04-25T23:50:00'); // Wednesday same week as targetReference
    });

    test('should properly adjust timestamp when day is after targetReference day of week', () => {
      const source = '2018-01-05T16:16:50'; // Friday, same week relative to sourceReference
      const timestamp = translateTimeRelativeToWeek(source, sourceReference, targetReference);
      expect(timestamp).toBe('2018-04-27T16:16:50'); // Friday same week as targetReference
    });
  });

  describe('week after', () => {
    test('should properly adjust timestamp when day is before targetReference day of week', () => {
      const source = '2018-01-08T23:50:00'; // Monday, 1 week after relative to sourceReference
      const timestamp = translateTimeRelativeToWeek(source, sourceReference, targetReference);
      expect(timestamp).toBe('2018-04-30T23:50:00'); // Monday 1 week after targetReference week
    });

    test('should properly adjust timestamp when day is same as targetReference day of week', () => {
      const source = '2018-01-10T23:50:00'; // Wednesday, same week relative to sourceReference
      const timestamp = translateTimeRelativeToWeek(source, sourceReference, targetReference);
      expect(timestamp).toBe('2018-05-02T23:50:00'); // Wednesday 1 week after targetReference week
    });

    test('should properly adjust timestamp when day is after targetReference day of week', () => {
      const source = '2018-01-12T16:16:50'; // Friday, same week relative to sourceReference
      const timestamp = translateTimeRelativeToWeek(source, sourceReference, targetReference);
      expect(timestamp).toBe('2018-05-04T16:16:50'); // Friday 1 week after targetReference week
    });
  });
});
