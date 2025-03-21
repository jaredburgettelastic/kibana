/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import { monaco } from './monaco_imports';
import type { LangModuleType, CustomLangModuleType } from './types';

export function registerLanguage(language: LangModuleType | CustomLangModuleType, force = false) {
  const { ID, lexerRules, languageConfiguration, foldingRangeProvider } = language;

  if (!force && monaco.languages.getLanguages().some((lang) => lang.id === ID)) {
    return;
  }

  monaco.languages.register({ id: ID });

  if ('languageThemeResolver' in language) {
    monaco.editor.registerLanguageThemeResolver(ID, language.languageThemeResolver);
  }

  monaco.languages.onLanguage(ID, async () => {
    if (lexerRules) {
      monaco.languages.setMonarchTokensProvider(ID, lexerRules);
    }

    if (languageConfiguration) {
      monaco.languages.setLanguageConfiguration(ID, languageConfiguration);
    }

    if (foldingRangeProvider) {
      monaco.languages.registerFoldingRangeProvider(ID, foldingRangeProvider);
    }

    if ('onLanguage' in language) {
      await language.onLanguage?.();
    }
  });
}

/**
 *
 * @deprecated avoid using this function, use `monaco.editor.registerLanguageThemeDefinition` instead
 */
export function registerTheme(id: string, themeData: monaco.editor.IStandaloneThemeData) {
  try {
    monaco.editor.defineTheme(id, themeData);
  } catch (e) {
    // nothing to be here
  }
}
