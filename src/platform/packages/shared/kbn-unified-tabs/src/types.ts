/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import type { CoreStart } from '@kbn/core/public';

export interface TabItem {
  id: string;
  label: string;
}

export interface TabMenuItemWithClick {
  'data-test-subj': string;
  name: string;
  label: string;
  onClick: () => void;
}

export interface TabsSizeConfig {
  isScrollable: boolean;
  regularTabMaxWidth: number;
  regularTabMinWidth: number;
  // TODO: extend with possibly different sizes for pinned tabs
}

export type TabMenuItem = TabMenuItemWithClick | 'divider';

export type GetTabMenuItems = (item: TabItem) => TabMenuItem[];

export interface TabsServices {
  core: {
    chrome?: CoreStart['chrome'];
  };
}
