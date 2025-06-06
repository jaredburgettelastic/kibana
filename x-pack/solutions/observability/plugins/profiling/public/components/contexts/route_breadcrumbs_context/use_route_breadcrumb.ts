/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { useCurrentRoute } from '@kbn/typed-react-router-config';
import { useContext, useEffect, useRef } from 'react';
import { castArray } from 'lodash';
import type { Breadcrumb } from '.';
import { RouteBreadcrumbsContext } from '.';

export function useRouteBreadcrumb(breadcrumb: Breadcrumb | Breadcrumb[]) {
  const api = useContext(RouteBreadcrumbsContext);

  if (!api) {
    throw new Error('Missing Breadcrumb API in context');
  }

  const { match } = useCurrentRoute();

  const matchedRoute = useRef(match?.route);

  useEffect(() => {
    if (matchedRoute.current && matchedRoute.current !== match?.route) {
      api.unset(matchedRoute.current);
    }

    matchedRoute.current = match?.route;

    if (matchedRoute.current) {
      api.set(matchedRoute.current, castArray(breadcrumb));
    }

    return () => {
      if (matchedRoute.current) {
        api.unset(matchedRoute.current);
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [matchedRoute.current, match?.route]);
}
