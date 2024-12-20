/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import { first } from 'rxjs';

import type { RouteDefinitionParams } from '.';

export function defineStatusRoute({ router, elasticsearch, preboot }: RouteDefinitionParams) {
  router.get(
    {
      path: '/internal/interactive_setup/status',
      security: {
        authz: {
          enabled: false,
          reason:
            'Interactive setup is strictly a "pre-boot" feature which cannot leverage conventional authorization.',
        },
      },
      validate: false,
      options: { authRequired: false },
    },
    async (context, request, response) => {
      // `connectionStatus$` is a `ReplaySubject` with a buffer size of 1 so `first()` operator will
      // always return the most recently emitted value. We can't use `connectionStatus$.toPromise()`
      // directly since the stream hasn't ended so it would never resolve.
      const connectionStatus = await elasticsearch.connectionStatus$.pipe(first()).toPromise();
      return response.ok({
        body: {
          connectionStatus,
          isSetupOnHold: preboot.isSetupOnHold(),
        },
      });
    }
  );
}
