/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

// This file is skipped
// @storybook/addon-storyshots is not supported in Jest 27+ https://github.com/storybookjs/storybook/issues/15916
// @storybook/addon-storyshots has been removed in Storybook 8 https://github.com/storybookjs/storybook/blob/next/MIGRATION.md#storyshots-has-been-removed

import fs from 'fs';
import { ReactChildren } from 'react';
import path from 'path';
import moment from 'moment';
import 'moment-timezone';
import ReactDOM from 'react-dom';

// @ts-expect-error untyped library
import styleSheetSerializer from 'jest-styled-components/src/styleSheetSerializer';
// @ts-expect-error untyped library
import { addSerializer } from 'jest-specific-snapshot';
import { createSerializer } from '@emotion/jest';
import { replaceEmotionPrefix } from '@elastic/eui/lib/test';

// Several of the renderers, used by the runtime, use jQuery.
import jquery from 'jquery';
// @ts-expect-error jQuery global
global.$ = jquery;
// @ts-expect-error jQuery global
global.jQuery = jquery;

// Set our default timezone to UTC for tests so we can generate predictable snapshots
moment.tz.setDefault('UTC');

// Freeze time for the tests for predictable snapshots
const testTime = new Date(Date.UTC(2019, 5, 1)); // June 1 2019
Date.now = jest.fn(() => testTime.getTime());

// Mock telemetry service
jest.mock('../public/lib/ui_metric', () => ({ trackCanvasUiMetric: () => {} }));

// Mock React Portal for components that use modals, tooltips, etc
// @ts-expect-error Portal mocks are notoriously difficult to type
ReactDOM.createPortal = jest.fn((element) => element);

// To be resolved by EUI team.
// https://github.com/elastic/eui/issues/3712
jest.mock('@elastic/eui/lib/components/overlay_mask/overlay_mask', () => {
  return {
    EuiOverlayMask: ({ children }: { children: ReactChildren }) => children,
  };
});

// Disabling this test due to https://github.com/elastic/eui/issues/2242
jest.mock(
  '../public/components/workpad_header/share_menu/flyout/__stories__/flyout.stories',
  () => {
    return 'Disabled Panel';
  }
);

// @ts-expect-error untyped library
import { EuiObserver } from '@elastic/eui/test-env/components/observer/observer';
jest.mock('@elastic/eui/test-env/components/observer/observer');
EuiObserver.mockImplementation(() => 'EuiObserver');

import { ExpressionInput } from '@kbn/presentation-util-plugin/public/components/expression_input';
jest.mock('@kbn/presentation-util-plugin/public/components/expression_input');
// @ts-expect-error
ExpressionInput.mockImplementation(() => 'ExpressionInput');

import Dropzone from 'react-dropzone';
jest.mock('react-dropzone');
// @ts-expect-error untyped library
Dropzone.mockImplementation(() => 'Dropzone');

// This element uses a `ref` and cannot be rendered by Jest snapshots.
import { RenderedElement } from '../shareable_runtime/components/rendered_element';
jest.mock('../shareable_runtime/components/rendered_element');
// @ts-expect-error
RenderedElement.mockImplementation(() => 'RenderedElement');

// Some of the code requires that this directory exists, but the tests don't actually require any css to be present
const cssDir = path.resolve(__dirname, '../../../../../../built_assets/css');
if (!fs.existsSync(cssDir)) {
  fs.mkdirSync(cssDir, { recursive: true });
}

addSerializer(styleSheetSerializer);

const emotionSerializer = createSerializer({
  classNameReplacer: replaceEmotionPrefix,
  includeStyles: false,
});
addSerializer(emotionSerializer);

// const converter = new Stories2SnapsConverter();

// Initialize Storyshots and build the Jest Snapshots
// initStoryshots({
//   configPath: path.resolve(__dirname),
//   framework: 'react',
//   asyncJest: true,
//   test: async ({ story, context, done }) => {
//     const renderer = create(createElement(story.render));
//     // wait until the element will perform all renders and resolve all promises (lazy loading, especially)
//     await act(() => new Promise((resolve) => setTimeout(resolve, 0)));
//     // save each snapshot to a different file (similar to "multiSnapshotWithOptions")
//     const snapshotFileName = converter.getSnapshotFileName(context);
//     expect(renderer).toMatchSpecificSnapshot(snapshotFileName);
//     done?.();
//   },
//   // Don't snapshot tests that start with 'redux'
//   storyNameRegex: /^((?!.*?redux).)*$/,
//   renderer: shallow,
// });
