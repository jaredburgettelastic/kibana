/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { FC } from 'react';
import React from 'react';
import { pick } from 'lodash';

import type { SavedSearch } from '@kbn/saved-search-plugin/public';
import type { DataView } from '@kbn/data-views-plugin/public';
import { StorageContextProvider } from '@kbn/ml-local-storage';
import { UrlStateProvider } from '@kbn/ml-url-state';
import { Storage } from '@kbn/kibana-utils-plugin/public';
import { DatePickerContextProvider, type DatePickerDependencies } from '@kbn/ml-date-picker';
import { UI_SETTINGS } from '@kbn/data-plugin/common';
import { LogRateAnalysisReduxProvider } from '@kbn/aiops-log-rate-analysis/state';

import type { AiopsAppContextValue } from '../../hooks/use_aiops_app_context';
import { AiopsAppContext } from '../../hooks/use_aiops_app_context';
import { DataSourceContext } from '../../hooks/use_data_source';
import { AIOPS_STORAGE_KEYS } from '../../types/storage';

import { LogRateAnalysisPage } from './log_rate_analysis_page';
import { timeSeriesDataViewWarning } from '../../application/utils/time_series_dataview_check';
import { FilterQueryContextProvider } from '../../hooks/use_filters_query';

const localStorage = new Storage(window.localStorage);

/**
 * Props for the LogRateAnalysisAppState component.
 */
export interface LogRateAnalysisAppStateProps {
  /** The data view to analyze. */
  dataView: DataView;
  /** The saved search to analyze. */
  savedSearch: SavedSearch | null;
  /** App context value */
  appContextValue: AiopsAppContextValue;
  /** Optional flag to indicate whether to show contextual insights */
  showContextualInsights?: boolean;
  /** Optional flag to indicate whether kibana is running in serverless */
  showFrozenDataTierChoice?: boolean;
}

export const LogRateAnalysisAppState: FC<LogRateAnalysisAppStateProps> = ({
  dataView,
  savedSearch,
  appContextValue,
  showContextualInsights = false,
  showFrozenDataTierChoice = true,
}) => {
  if (!dataView) return null;

  const warning = timeSeriesDataViewWarning(dataView, 'log_rate_analysis');

  if (warning !== null) {
    return <>{warning}</>;
  }
  const CasesContext = appContextValue.cases?.ui.getCasesContext() ?? React.Fragment;
  const casesPermissions = appContextValue.cases?.helpers.canUseCases();

  const datePickerDeps: DatePickerDependencies = {
    ...pick(appContextValue, [
      'data',
      'http',
      'notifications',
      'theme',
      'uiSettings',
      'userProfile',
      'i18n',
    ]),
    uiSettingsKeys: UI_SETTINGS,
    showFrozenDataTierChoice,
  };

  return (
    <AiopsAppContext.Provider value={appContextValue}>
      <CasesContext permissions={casesPermissions!} owner={[]}>
        <UrlStateProvider>
          <DataSourceContext.Provider value={{ dataView, savedSearch }}>
            <LogRateAnalysisReduxProvider>
              <StorageContextProvider storage={localStorage} storageKeys={AIOPS_STORAGE_KEYS}>
                <DatePickerContextProvider {...datePickerDeps}>
                  <FilterQueryContextProvider>
                    <LogRateAnalysisPage showContextualInsights={showContextualInsights} />
                  </FilterQueryContextProvider>
                </DatePickerContextProvider>
              </StorageContextProvider>
            </LogRateAnalysisReduxProvider>
          </DataSourceContext.Provider>
        </UrlStateProvider>
      </CasesContext>
    </AiopsAppContext.Provider>
  );
};
