/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import { VIEW_MODE } from '@kbn/saved-search-plugin/public';

/**
 * Returns a valid view mode
 * @param viewMode
 * @param isEsqlMode
 */
export const getValidViewMode = ({
  viewMode,
  isEsqlMode,
}: {
  viewMode?: VIEW_MODE;
  isEsqlMode: boolean;
}): VIEW_MODE | undefined => {
  if (viewMode === VIEW_MODE.PATTERN_LEVEL && isEsqlMode) {
    // only this mode is supported for ES|QL languages
    return VIEW_MODE.DOCUMENT_LEVEL;
  }

  return viewMode;
};
