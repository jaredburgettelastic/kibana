/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import { EcsFlat } from '@elastic/ecs';
import { ActionVariable } from '@kbn/alerting-types';
import type { HttpStart } from '@kbn/core-http-browser';
import { useQuery } from '@tanstack/react-query';
import {
  fetchRuleTypeAadTemplateFields,
  getDescription,
} from '@kbn/alerts-ui-shared/src/common/apis';

export interface UseLoadRuleTypeAadTemplateFieldProps {
  http: HttpStart;
  ruleTypeId?: string;
  enabled: boolean;
  cacheTime?: number;
}

export const useLoadRuleTypeAadTemplateField = (props: UseLoadRuleTypeAadTemplateFieldProps) => {
  const { http, ruleTypeId, enabled, cacheTime } = props;

  const queryFn = async () => {
    if (!ruleTypeId) {
      return;
    }
    return fetchRuleTypeAadTemplateFields({ http, ruleTypeId });
  };

  const {
    data = [],
    isLoading,
    isFetching,
    isInitialLoading,
  } = useQuery({
    queryKey: ['useLoadRuleTypeAadTemplateField', ruleTypeId],
    queryFn,
    select: (dataViewFields) => {
      return dataViewFields?.map<ActionVariable>((d) => ({
        name: d.name,
        description: getDescription(d.name, EcsFlat),
      }));
    },
    cacheTime,
    refetchOnWindowFocus: false,
    enabled,
  });

  return {
    data,
    isInitialLoading,
    isLoading: isLoading || isFetching,
  };
};
