/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { act } from 'react-dom/test-utils';
import React from 'react';

import { registerTestBed, TestBed } from '@kbn/test-jest-helpers';
import { usageCollectionPluginMock } from '@kbn/usage-collection-plugin/public/mocks';
import { docLinksServiceMock } from '@kbn/core/public/mocks';
import { Props } from '..';
import { ProcessorsEditorWithDeps } from './processors_editor';
import { documentationService, uiMetricService } from '../../../services';

jest.mock('@elastic/eui', () => {
  const original = jest.requireActual('@elastic/eui');

  return {
    ...original,
    // Mocking EuiComboBox, as it utilizes "react-virtualized" for rendering search suggestions,
    // which does not produce a valid component wrapper
    EuiComboBox: (props: any) => (
      <input
        data-test-subj={props['data-test-subj'] || 'mockComboBox'}
        data-currentvalue={props.selectedOptions}
        onChange={async (syntheticEvent: any) => {
          props.onChange([syntheticEvent['0']]);
        }}
      />
    ),
  };
});

jest.mock('@kbn/code-editor', () => {
  const original = jest.requireActual('@kbn/code-editor');
  return {
    ...original,
    // Mocking CodeEditor, which uses React Monaco under the hood
    CodeEditor: (props: any) => (
      <input
        data-test-subj={props['data-test-subj'] || 'mockCodeEditor'}
        data-currentvalue={props.value}
        onChange={(e: any) => {
          props.onChange(e.jsonContent);
        }}
      />
    ),
  };
});

jest.mock('react-virtualized/dist/commonjs/AutoSizer', () => ({ children }: { children: any }) => (
  <div>{children({ height: 500, width: 500 })}</div>
));

const testBedSetup = registerTestBed<TestSubject>(
  (props: Props) => <ProcessorsEditorWithDeps {...props} />,
  {
    doMountAsync: false,
  }
);

export interface SetupResult extends TestBed<TestSubject> {
  actions: ReturnType<typeof createActions>;
}

export const setupEnvironment = () => {
  // Initialize mock services
  uiMetricService.setup(usageCollectionPluginMock.createSetupContract());
  documentationService.setup(docLinksServiceMock.createStartContract());
};

/**
 * We make heavy use of "processorSelector" in these actions. They are a way to uniquely identify
 * a processor and are a stringified version of {@link ProcessorSelector}.
 *
 * @remark
 * See also {@link selectorToDataTestSubject}.
 */
const createActions = (testBed: TestBed<TestSubject>) => {
  const { find, component } = testBed;

  return {
    async addProcessor(processorsSelector: string, type: string, options: Record<string, any>) {
      find(`${processorsSelector}.addProcessorButton`).simulate('click');
      await act(async () => {
        find('processorTypeSelector.input').simulate('change', [{ value: type, label: type }]);
        jest.advanceTimersByTime(0); // advance timers to allow the form to validate
      });
      component.update();
      await act(async () => {
        find('processorOptionsEditor').simulate('change', {
          jsonContent: JSON.stringify(options),
        });
        jest.advanceTimersByTime(0); // advance timers to allow the form to validate
      });
      component.update();
      await act(async () => {
        find('addProcessorForm.submitButton').simulate('click');
        jest.advanceTimersByTime(0); // advance timers to allow the form to validate
      });
      component.update();
    },

    async setProcessorType(type: string) {
      await act(async () => {
        find('processorTypeSelector.input').simulate('change', [{ value: type }]);
      });
      component.update();
    },

    removeProcessor(processorSelector: string) {
      find(`${processorSelector}.moreMenu.button`).simulate('click');
      find(`${processorSelector}.moreMenu.deleteButton`).simulate('click');
      act(() => {
        find('removeProcessorConfirmationModal.confirmModalConfirmButton').simulate('click');
      });
    },

    moveProcessor(processorSelector: string, dropZoneSelector: string) {
      act(() => {
        find(`${processorSelector}.moveItemButton`).simulate('click');
      });
      component.update();
      act(() => {
        find(dropZoneSelector).simulate('click');
      });
      component.update();
    },

    async addOnFailureProcessor(
      processorSelector: string,
      type: string,
      options: Record<string, any>
    ) {
      find(`${processorSelector}.moreMenu.button`).simulate('click');
      find(`${processorSelector}.moreMenu.addOnFailureButton`).simulate('click');
      await act(async () => {
        find('processorTypeSelector.input').simulate('change', [{ value: type, label: type }]);
        jest.advanceTimersByTime(0); // advance timers to allow the form to validate
      });
      component.update();
      await act(async () => {
        find('processorOptionsEditor').simulate('change', {
          jsonContent: JSON.stringify(options),
        });
        jest.advanceTimersByTime(0); // advance timers to allow the form to validate
      });
      await act(async () => {
        find('addProcessorForm.submitButton').simulate('click');
        jest.advanceTimersByTime(0); // advance timers to allow the form to validate
      });
    },

    startAndCancelMove(processorSelector: string) {
      act(() => {
        find(`${processorSelector}.moveItemButton`).simulate('click');
      });
      component.update();
      act(() => {
        find(`${processorSelector}.cancelMoveItemButton`).simulate('click');
      });
      component.update();
    },

    duplicateProcessor(processorSelector: string) {
      find(`${processorSelector}.moreMenu.button`).simulate('click');
      act(() => {
        find(`${processorSelector}.moreMenu.duplicateButton`).simulate('click');
      });
    },
    openProcessorEditor: (processorSelector: string) => {
      act(() => {
        find(`${processorSelector}.manageItemButton`).simulate('click');
      });
      component.update();
    },
    submitProcessorForm: async () => {
      await act(async () => {
        find('editProcessorForm.submitButton').simulate('click');
        jest.advanceTimersByTime(0); // advance timers to allow the form to validate
      });
    },
  };
};

export const setup = async (props: Props): Promise<SetupResult> => {
  const testBed = testBedSetup(props);
  return {
    ...testBed,
    actions: createActions(testBed),
  };
};

type TestSubject =
  | 'pipelineEditorDoneButton'
  | 'pipelineEditorOnFailureToggle'
  | 'addProcessorsButtonLevel1'
  | 'editProcessorForm'
  | 'editProcessorForm.submitButton'
  | 'addProcessorForm.submitButton'
  | 'addProcessorForm'
  | 'processorOptionsEditor'
  | 'processorSettingsFormFlyout'
  | 'processorTypeSelector'
  | 'pipelineEditorOnFailureTree'
  | 'processorsEmptyPrompt'
  | string;
