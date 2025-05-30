/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { action } from '@storybook/addon-actions';
import type { Meta } from '@storybook/react';
import React from 'react';
import moment from 'moment';
import { WorkpadFilters } from '../workpad_filters.component';
import { FiltersGroup as FiltersGroupType } from '../types';
import { Filter } from '../../../../types';

const timeFormat = 'MM.dd.YYYY HH:mm';

const filters: Filter[] = [
  { type: 'exactly', column: 'project', value: 'kibana', filterGroup: 'Group 1' },
  {
    type: 'time',
    column: '@timestamp',
    value: {
      from: moment('1.01.2021 8:15', timeFormat).format(),
      to: moment('2.01.2021 17:22', timeFormat).format(),
    },
    filterGroup: 'Group 1',
  },
  { type: 'exactly', column: 'country', value: 'US', filterGroup: 'Group 2' },
  {
    type: 'time',
    column: 'time',
    value: {
      from: moment('05.21.2021 10:50', timeFormat).format(),
      to: moment('05.22.2021 4:40', timeFormat).format(),
    },
    filterGroup: 'Group 2',
  },
];

const filtersGroups: FiltersGroupType[] = [
  {
    name: filters[0].filterGroup,
    filters: [filters[0], filters[1]],
  },
  {
    name: filters[2].filterGroup,
    filters: [filters[2], filters[3]],
  },
];

export default {
  title: 'components/WorkpadFilters/WorkpadFiltersComponent',

  decorators: [
    (story) => (
      <div>
        <div className="canvasLayout__sidebar">
          <div style={{ width: '100%' }}>{story()}</div>
        </div>
      </div>
    ),
  ],
} as Meta;

export const Default = {
  render: () => (
    <WorkpadFilters filtersGroups={filtersGroups} onGroupByChange={action('onGroupByChange')} />
  ),

  name: 'default',
};

export const FiltersGroupsWithoutName = {
  render: () => (
    <WorkpadFilters
      filtersGroups={[
        {
          name: null,
          filters: filtersGroups.reduce<Filter[]>((acc, group) => [...acc, ...group.filters], []),
        },
      ]}
      groupFiltersByField={'column'}
      onGroupByChange={action('onGroupByChange')}
    />
  ),

  name: 'Filters groups without name',
};

export const FiltersGroupsWithoutGroupName = {
  render: () => (
    <WorkpadFilters
      filtersGroups={[
        {
          name: null,
          filters: filtersGroups.reduce<Filter[]>((acc, group) => [...acc, ...group.filters], []),
        },
      ]}
      groupFiltersByField={'filterGroup'}
      onGroupByChange={action('onGroupByChange')}
    />
  ),

  name: 'Filters groups without group name',
};

export const FiltersGroupsWithoutNameAndFilters = {
  render: () => (
    <WorkpadFilters
      filtersGroups={[{ name: null, filters: [] }]}
      onGroupByChange={action('onGroupByChange')}
    />
  ),

  name: 'Filters groups without name and filters',
};

export const EmptyFiltersGroups = {
  render: () => <WorkpadFilters filtersGroups={[]} onGroupByChange={action('onGroupByChange')} />,

  name: 'Empty filters groups',
};
