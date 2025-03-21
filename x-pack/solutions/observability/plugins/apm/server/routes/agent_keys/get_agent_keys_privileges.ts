/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import type { CoreStart } from '@kbn/core/server';
import type { ApmPluginRequestHandlerContext } from '../typings';

export interface AgentKeysPrivilegesResponse {
  areApiKeysEnabled: boolean;
  isAdmin: boolean;
  canManage: boolean;
}

export async function getAgentKeysPrivileges({
  context,
  coreStart,
}: {
  context: ApmPluginRequestHandlerContext;
  coreStart: CoreStart;
}): Promise<AgentKeysPrivilegesResponse> {
  const esClient = (await context.core).elasticsearch.client;
  const [securityHasPrivilegesResponse, areApiKeysEnabled] = await Promise.all([
    esClient.asCurrentUser.security.hasPrivileges({
      cluster: ['manage_security', 'manage_api_key', 'manage_own_api_key'],
    }),
    coreStart.security.authc.apiKeys.areAPIKeysEnabled(),
  ]);

  const {
    cluster: {
      manage_security: manageSecurity,
      manage_api_key: manageApiKey,
      manage_own_api_key: manageOwnApiKey,
    },
  } = securityHasPrivilegesResponse;

  const isAdmin = manageSecurity || manageApiKey;
  const canManage = manageSecurity || manageApiKey || manageOwnApiKey;

  return {
    areApiKeysEnabled,
    isAdmin,
    canManage,
  };
}
