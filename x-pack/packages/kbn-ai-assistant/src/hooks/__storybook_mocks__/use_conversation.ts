/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { Subject } from 'rxjs';

export function useConversation() {
  return {
    conversation: {},
    state: 'idle',
    next: new Subject(),
    stop: () => {},
    messages: [],
    saveTitle: () => {},
    scopes: ['all'],
  };
}
