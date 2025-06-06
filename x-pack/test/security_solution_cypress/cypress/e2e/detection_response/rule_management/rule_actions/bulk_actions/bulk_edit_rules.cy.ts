/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  deleteAlertsAndRules,
  deletePrebuiltRulesAssets,
} from '../../../../../tasks/api_calls/common';
import {
  MODAL_CONFIRMATION_BTN,
  RULES_TAGS_POPOVER_BTN,
  MODAL_ERROR_BODY,
} from '../../../../../screens/alerts_detection_rules';

import {
  RULES_BULK_EDIT_INDEX_PATTERNS_WARNING,
  RULES_BULK_EDIT_TAGS_WARNING,
  RULES_BULK_EDIT_TIMELINE_TEMPLATES_WARNING,
  TAGS_RULE_BULK_MENU_ITEM,
  INDEX_PATTERNS_RULE_BULK_MENU_ITEM,
  APPLY_TIMELINE_RULE_BULK_MENU_ITEM,
  RULES_BULK_EDIT_INVESTIGATION_FIELDS_WARNING,
} from '../../../../../screens/rules_bulk_actions';

import {
  INVESTIGATION_FIELDS_DETAILS,
  TIMELINE_TEMPLATE_DETAILS,
} from '../../../../../screens/rule_details';

import { EUI_CHECKBOX, EUI_FILTER_SELECT_ITEM } from '../../../../../screens/common/controls';

import {
  selectAllRules,
  goToRuleDetailsOf,
  testAllTagsBadges,
  testTagsBadge,
  testMultipleSelectedRulesLabel,
  clickErrorToastBtn,
  cancelConfirmationModal,
  selectRulesByName,
  getRulesManagementTableRows,
  getRuleRow,
  disableAutoRefresh,
} from '../../../../../tasks/alerts_detection_rules';

import {
  typeIndexPatterns,
  waitForBulkEditActionToFinish,
  submitBulkEditForm,
  clickAddIndexPatternsMenuItem,
  checkMachineLearningRulesCannotBeModified,
  checkEsqlRulesCannotBeModified,
  openBulkEditAddTagsForm,
  openBulkEditDeleteTagsForm,
  typeTags,
  openTagsSelect,
  openBulkActionsMenu,
  clickApplyTimelineTemplatesMenuItem,
  checkOverwriteTagsCheckbox,
  checkOverwriteIndexPatternsCheckbox,
  openBulkEditAddIndexPatternsForm,
  openBulkEditDeleteIndexPatternsForm,
  selectTimelineTemplate,
  checkTagsInTagsFilter,
  clickUpdateScheduleMenuItem,
  typeScheduleInterval,
  typeScheduleLookback,
  setScheduleLookbackTimeUnit,
  setScheduleIntervalTimeUnit,
  assertRuleScheduleValues,
  assertUpdateScheduleWarningExists,
  assertDefaultValuesAreAppliedToScheduleFields,
  openBulkEditAddInvestigationFieldsForm,
  typeInvestigationFields,
  checkOverwriteInvestigationFieldsCheckbox,
  openBulkEditDeleteInvestigationFieldsForm,
} from '../../../../../tasks/rules_bulk_actions';

import { createRuleAssetSavedObject } from '../../../../../helpers/rules';
import {
  hasIndexPatterns,
  getDetails,
  hasInvestigationFields,
  assertDetailsNotExist,
} from '../../../../../tasks/rule_details';
import { login } from '../../../../../tasks/login';
import { visitRulesManagementTable } from '../../../../../tasks/rules_management';
import { createRule } from '../../../../../tasks/api_calls/rules';
import { loadPrepackagedTimelineTemplates } from '../../../../../tasks/api_calls/timelines';
import { resetRulesTableState } from '../../../../../tasks/common';

import {
  getEqlRule,
  getEsqlRule,
  getNewThreatIndicatorRule,
  getNewRule,
  getNewThresholdRule,
  getMachineLearningRule,
  getNewTermsRule,
} from '../../../../../objects/rule';

import {
  createAndInstallMockedPrebuiltRules,
  preventPrebuiltRulesPackageInstallation,
} from '../../../../../tasks/api_calls/prebuilt_rules';
import { setRowsPerPageTo, sortByTableColumn } from '../../../../../tasks/table_pagination';

const RULE_NAME = 'Custom rule for bulk actions';
const EUI_SELECTABLE_LIST_ITEM_SR_TEXT = '. To check this option, press Enter.';

const prePopulatedIndexPatterns = ['index-1-*', 'index-2-*', 'auditbeat-*'];
const prePopulatedTags = ['test-default-tag-1', 'test-default-tag-2'];
const prePopulatedInvestigationFields = ['agent.version', 'host.name'];

const expectedNumberOfMachineLearningRulesToBeEdited = 1;

const defaultRuleData = {
  index: prePopulatedIndexPatterns,
  tags: prePopulatedTags,
  investigation_fields: { field_names: prePopulatedInvestigationFields },
  timeline_title: 'Generic Threat Match Timeline',
  timeline_id: '495ad7a7-316e-4544-8a0f-9c098daee76e',
};

describe(
  'Detection rules, bulk edit',
  { tags: ['@ess', '@serverless', '@skipInServerlessMKI'] },
  () => {
    beforeEach(() => {
      login();
      // Make sure persisted rules table state is cleared
      resetRulesTableState();
      deleteAlertsAndRules();
      deletePrebuiltRulesAssets();

      const PREBUILT_RULES = [
        createRuleAssetSavedObject({
          ...defaultRuleData,
          name: 'Prebuilt rule 1',
          rule_id: 'rule_1',
        }),
        createRuleAssetSavedObject({
          ...defaultRuleData,
          name: 'Prebuilt rule 2',
          rule_id: 'rule_2',
        }),
      ];

      createAndInstallMockedPrebuiltRules(PREBUILT_RULES);

      createRule(getNewRule({ name: RULE_NAME, ...defaultRuleData, rule_id: '1', enabled: false }));
      createRule(
        getEqlRule({ ...defaultRuleData, rule_id: '2', name: 'New EQL Rule', enabled: false })
      );
      createRule(
        getMachineLearningRule({
          name: 'New ML Rule Test',
          tags: prePopulatedTags,
          investigation_fields: { field_names: prePopulatedInvestigationFields },
          enabled: false,
        })
      );
      createRule(
        getNewThreatIndicatorRule({
          ...defaultRuleData,
          rule_id: '4',
          name: 'Threat Indicator Rule Test',
          enabled: false,
        })
      );
      createRule(
        getNewThresholdRule({
          ...defaultRuleData,
          rule_id: '5',
          name: 'Threshold Rule',
          enabled: false,
        })
      );
      createRule(
        getNewTermsRule({
          ...defaultRuleData,
          rule_id: '6',
          name: 'New Terms Rule',
          enabled: false,
        })
      );

      visitRulesManagementTable();
      disableAutoRefresh();
    });

    describe('Prerequisites', () => {
      it('No rules selected', () => {
        openBulkActionsMenu();

        // when no rule selected all bulk edit options should be disabled
        cy.get(TAGS_RULE_BULK_MENU_ITEM).should('be.disabled');
        cy.get(INDEX_PATTERNS_RULE_BULK_MENU_ITEM).should('be.disabled');
        cy.get(APPLY_TIMELINE_RULE_BULK_MENU_ITEM).should('be.disabled');
      });

      it('should not lose rules selection after edit action', () => {
        const rulesToUpdate = [RULE_NAME, 'New EQL Rule', 'New Terms Rule'] as const;
        // Switch to 5 rules per page, to have few pages in pagination(ideal way to test auto refresh and selection of few items)
        setRowsPerPageTo(5);
        // and make the rules order isn't changing (set sorting by rule name) over time if rules are run
        sortByTableColumn('Rule');
        selectRulesByName(rulesToUpdate);

        // open add tags form and add 2 new tags
        openBulkEditAddTagsForm();
        typeTags(['new-tag-1']);
        submitBulkEditForm();
        waitForBulkEditActionToFinish({ updatedCount: rulesToUpdate.length });

        testMultipleSelectedRulesLabel(rulesToUpdate.length);
        // check if first four(rulesCount) rules still selected and tags are updated
        for (const ruleName of rulesToUpdate) {
          getRuleRow(ruleName).find(EUI_CHECKBOX).should('be.checked');
          getRuleRow(ruleName)
            .find(RULES_TAGS_POPOVER_BTN)
            .each(($el) => {
              testTagsBadge($el, prePopulatedTags.concat(['new-tag-1']));
            });
        }
      });
    });

    describe('Tags actions', () => {
      it('Display list of tags in tags select', () => {
        selectAllRules();

        openBulkEditAddTagsForm();
        openTagsSelect();

        cy.get(EUI_FILTER_SELECT_ITEM)
          .should('have.length', prePopulatedTags.length)
          .each(($el, index) => {
            cy.wrap($el).should('have.text', prePopulatedTags[index]);
          });
      });

      it('Add tags', () => {
        getRulesManagementTableRows().then((rows) => {
          const tagsToBeAdded = ['tag-to-add-1', 'tag-to-add-2'];
          const resultingTags = [...prePopulatedTags, ...tagsToBeAdded];

          // check if only pre-populated tags exist in the tags filter
          checkTagsInTagsFilter(prePopulatedTags, EUI_SELECTABLE_LIST_ITEM_SR_TEXT);

          selectAllRules();

          // open add tags form and add 2 new tags
          openBulkEditAddTagsForm();
          typeTags(tagsToBeAdded);
          submitBulkEditForm();
          waitForBulkEditActionToFinish({ updatedCount: rows.length });

          // check if all rules have been updated with new tags
          testAllTagsBadges(resultingTags);

          // check that new tags were added to tags filter
          // tags in tags filter sorted alphabetically
          const resultingTagsInFilter = [...resultingTags].sort();
          checkTagsInTagsFilter(resultingTagsInFilter, EUI_SELECTABLE_LIST_ITEM_SR_TEXT);
        });
      });

      it('Display success toast after adding tags', () => {
        getRulesManagementTableRows().then((rows) => {
          const tagsToBeAdded = ['tag-to-add-1', 'tag-to-add-2'];

          // check if only pre-populated tags exist in the tags filter
          checkTagsInTagsFilter(prePopulatedTags, EUI_SELECTABLE_LIST_ITEM_SR_TEXT);

          selectAllRules();

          // open add tags form and add 2 new tags
          openBulkEditAddTagsForm();
          typeTags(tagsToBeAdded);
          submitBulkEditForm();
          waitForBulkEditActionToFinish({ updatedCount: rows.length });
        });
      });

      it('Overwrite tags', () => {
        getRulesManagementTableRows().then((rows) => {
          const tagsToOverwrite = ['overwrite-tag-1'];

          // check if only pre-populated tags exist in the tags filter
          checkTagsInTagsFilter(prePopulatedTags, EUI_SELECTABLE_LIST_ITEM_SR_TEXT);

          selectAllRules();

          // open add tags form, check overwrite tags and warning message, type tags
          openBulkEditAddTagsForm();
          checkOverwriteTagsCheckbox();

          cy.get(RULES_BULK_EDIT_TAGS_WARNING).should(
            'have.text',
            `You’re about to overwrite tags for ${rows.length} selected rules, press Save to apply changes.`
          );

          typeTags(tagsToOverwrite);
          submitBulkEditForm();
          waitForBulkEditActionToFinish({ updatedCount: rows.length });

          // check if all rules have been updated with new tags
          testAllTagsBadges(tagsToOverwrite);

          // check that only new tags are in the tag filter
          checkTagsInTagsFilter(tagsToOverwrite, EUI_SELECTABLE_LIST_ITEM_SR_TEXT);
        });
      });

      it('Delete tags from', () => {
        getRulesManagementTableRows().then((rows) => {
          const tagsToDelete = prePopulatedTags.slice(0, 1);
          const resultingTags = prePopulatedTags.slice(1);

          // check if only pre-populated tags exist in the tags filter
          checkTagsInTagsFilter(prePopulatedTags, EUI_SELECTABLE_LIST_ITEM_SR_TEXT);

          selectAllRules();

          // open add tags form, check overwrite tags, type tags
          openBulkEditDeleteTagsForm();
          typeTags(tagsToDelete);
          submitBulkEditForm();
          waitForBulkEditActionToFinish({ updatedCount: rows.length });

          // check tags has been removed from all rules
          testAllTagsBadges(resultingTags);

          // check that tags were removed from the tag filter
          checkTagsInTagsFilter(resultingTags, EUI_SELECTABLE_LIST_ITEM_SR_TEXT);
        });
      });
    });

    describe('Index patterns', () => {
      it('Index pattern action applied, including machine learning: user proceeds with edit of non machine learning rule', () => {
        getRulesManagementTableRows().then((rows) => {
          const indexPattersToBeAdded = ['index-to-add-1-*', 'index-to-add-2-*'];
          const resultingIndexPatterns = [...prePopulatedIndexPatterns, ...indexPattersToBeAdded];

          selectAllRules();
          clickAddIndexPatternsMenuItem();

          // confirm editing all rules, that are not Machine Learning
          checkMachineLearningRulesCannotBeModified(expectedNumberOfMachineLearningRulesToBeEdited);
          cy.get(MODAL_CONFIRMATION_BTN).click();

          typeIndexPatterns(indexPattersToBeAdded);
          submitBulkEditForm();

          waitForBulkEditActionToFinish({
            updatedCount: rows.length - expectedNumberOfMachineLearningRulesToBeEdited,
          });

          // check if rule has been updated
          goToRuleDetailsOf(RULE_NAME);
          hasIndexPatterns(resultingIndexPatterns.join(''));
        });
      });

      it('Index pattern action applied to all rules, including machine learning: user cancels action', () => {
        selectAllRules();
        clickAddIndexPatternsMenuItem();

        // confirm editing all rules, that are not Machine Learning
        checkMachineLearningRulesCannotBeModified(expectedNumberOfMachineLearningRulesToBeEdited);

        // user cancels action and modal disappears
        cancelConfirmationModal();
      });

      it('Add index patterns', () => {
        getRulesManagementTableRows().then((rows) => {
          const indexPattersToBeAdded = ['index-to-add-1-*', 'index-to-add-2-*'];
          const resultingIndexPatterns = [...prePopulatedIndexPatterns, ...indexPattersToBeAdded];

          // select only rules that are not ML
          selectRulesByName([
            RULE_NAME,
            'New EQL Rule',
            'Threat Indicator Rule Test',
            'Threshold Rule',
            'New Terms Rule',
            'Prebuilt rule 1',
            'Prebuilt rule 2',
          ]);

          openBulkEditAddIndexPatternsForm();
          typeIndexPatterns(indexPattersToBeAdded);
          submitBulkEditForm();

          waitForBulkEditActionToFinish({
            updatedCount: rows.length - expectedNumberOfMachineLearningRulesToBeEdited,
          });

          // check if rule has been updated
          goToRuleDetailsOf(RULE_NAME);
          hasIndexPatterns(resultingIndexPatterns.join(''));
        });
      });

      it('Display success toast after editing the index pattern', () => {
        getRulesManagementTableRows().then((rows) => {
          const indexPattersToBeAdded = ['index-to-add-1-*', 'index-to-add-2-*'];

          // select only rules that are not ML
          selectRulesByName([
            RULE_NAME,
            'New EQL Rule',
            'Threat Indicator Rule Test',
            'Threshold Rule',
            'New Terms Rule',
            'Prebuilt rule 1',
            'Prebuilt rule 2',
          ]);

          openBulkEditAddIndexPatternsForm();
          typeIndexPatterns(indexPattersToBeAdded);
          submitBulkEditForm();

          waitForBulkEditActionToFinish({
            updatedCount: rows.length - expectedNumberOfMachineLearningRulesToBeEdited,
          });
        });
      });

      it('Overwrite index patterns', () => {
        const rulesToSelect = [
          RULE_NAME,
          'New EQL Rule',
          'Threat Indicator Rule Test',
          'Threshold Rule',
          'New Terms Rule',
          'Prebuilt rule 1',
          'Prebuilt rule 2',
        ] as const;
        const indexPattersToWrite = ['index-to-write-1-*', 'index-to-write-2-*'];

        // select only rules that are not ML
        selectRulesByName(rulesToSelect);

        openBulkEditAddIndexPatternsForm();

        // check overwrite index patterns checkbox, ensure warning message is displayed and type index patterns
        checkOverwriteIndexPatternsCheckbox();
        cy.get(RULES_BULK_EDIT_INDEX_PATTERNS_WARNING).should(
          'have.text',
          `You’re about to overwrite index patterns for ${rulesToSelect.length} selected rules, press Save to apply changes.`
        );

        typeIndexPatterns(indexPattersToWrite);
        submitBulkEditForm();

        waitForBulkEditActionToFinish({ updatedCount: rulesToSelect.length });

        // check if rule has been updated
        goToRuleDetailsOf(RULE_NAME);
        hasIndexPatterns(indexPattersToWrite.join(''));
      });

      it('Delete index patterns', () => {
        const rulesToSelect = [
          RULE_NAME,
          'New EQL Rule',
          'Threat Indicator Rule Test',
          'Threshold Rule',
          'New Terms Rule',
          'Prebuilt rule 1',
          'Prebuilt rule 2',
        ] as const;
        const indexPatternsToDelete = prePopulatedIndexPatterns.slice(0, 1);
        const resultingIndexPatterns = prePopulatedIndexPatterns.slice(1);

        // select only not ML rules
        selectRulesByName(rulesToSelect);

        openBulkEditDeleteIndexPatternsForm();
        typeIndexPatterns(indexPatternsToDelete);
        submitBulkEditForm();

        waitForBulkEditActionToFinish({ updatedCount: rulesToSelect.length });

        // check if rule has been updated
        goToRuleDetailsOf(RULE_NAME);
        hasIndexPatterns(resultingIndexPatterns.join(''));
      });

      it('Delete all index patterns', () => {
        const rulesToSelect = [
          RULE_NAME,
          'New EQL Rule',
          'Threat Indicator Rule Test',
          'Threshold Rule',
          'New Terms Rule',
          'Prebuilt rule 1',
          'Prebuilt rule 2',
        ] as const;

        // select only rules that are not ML
        selectRulesByName(rulesToSelect);

        openBulkEditDeleteIndexPatternsForm();
        typeIndexPatterns(prePopulatedIndexPatterns);
        submitBulkEditForm();

        // error toast should be displayed that that rules edit failed
        waitForBulkEditActionToFinish({ failedCount: rulesToSelect.length });

        // on error toast button click display error that index patterns can't be empty
        clickErrorToastBtn();
        cy.contains(MODAL_ERROR_BODY, "Index patterns can't be empty");
      });
    });

    describe('Investigation fields actions', () => {
      it('Add investigation fields', () => {
        getRulesManagementTableRows().then((rows) => {
          const fieldsToBeAdded = ['source.ip', 'destination.ip'];
          const resultingFields = [...prePopulatedInvestigationFields, ...fieldsToBeAdded];

          selectAllRules();

          // open add highlighted fields form and add 2 new fields
          openBulkEditAddInvestigationFieldsForm();
          typeInvestigationFields(fieldsToBeAdded);
          submitBulkEditForm();
          waitForBulkEditActionToFinish({ updatedCount: rows.length });

          // check if rule has been updated
          goToRuleDetailsOf(RULE_NAME);
          hasInvestigationFields(resultingFields.join(''));
        });
      });

      it('Overwrite investigation fields', () => {
        getRulesManagementTableRows().then((rows) => {
          const fieldsToOverwrite = ['source.ip'];

          selectAllRules();

          // open add tags form, check overwrite tags and warning message, type tags
          openBulkEditAddInvestigationFieldsForm();
          checkOverwriteInvestigationFieldsCheckbox();

          cy.get(RULES_BULK_EDIT_INVESTIGATION_FIELDS_WARNING).should(
            'have.text',
            `You’re about to overwrite custom highlighted fields for the ${rows.length} rules you selected. To apply and save the changes, click Save.`
          );

          typeInvestigationFields(fieldsToOverwrite);
          submitBulkEditForm();
          waitForBulkEditActionToFinish({ updatedCount: rows.length });

          // check if rule has been updated
          goToRuleDetailsOf(RULE_NAME);
          hasInvestigationFields(fieldsToOverwrite.join(''));
        });
      });

      it('Delete investigation fields', () => {
        getRulesManagementTableRows().then((rows) => {
          const fieldsToDelete = prePopulatedInvestigationFields.slice(0, 1);
          const resultingFields = prePopulatedInvestigationFields.slice(1);

          selectAllRules();

          // open add tags form, check overwrite tags, type tags
          openBulkEditDeleteInvestigationFieldsForm();
          typeInvestigationFields(fieldsToDelete);
          submitBulkEditForm();
          waitForBulkEditActionToFinish({ updatedCount: rows.length });

          // check if rule has been updated
          goToRuleDetailsOf(RULE_NAME);
          hasInvestigationFields(resultingFields.join(''));
        });
      });

      it('Delete all investigation fields', () => {
        getRulesManagementTableRows().then((rows) => {
          selectAllRules();

          openBulkEditDeleteInvestigationFieldsForm();
          typeInvestigationFields(prePopulatedInvestigationFields);
          submitBulkEditForm();
          waitForBulkEditActionToFinish({ updatedCount: rows.length });

          // check if rule has been updated
          goToRuleDetailsOf(RULE_NAME);
          assertDetailsNotExist(INVESTIGATION_FIELDS_DETAILS);
        });
      });
    });

    describe('Timeline templates', () => {
      beforeEach(() => {
        loadPrepackagedTimelineTemplates();
      });

      it('Apply timeline template', () => {
        getRulesManagementTableRows().then((rows) => {
          const timelineTemplateName = 'Generic Endpoint Timeline';

          selectAllRules();

          // open Timeline template form, check warning, select timeline template
          clickApplyTimelineTemplatesMenuItem();
          cy.get(RULES_BULK_EDIT_TIMELINE_TEMPLATES_WARNING).contains(
            `You're about to apply changes to ${rows.length} selected rules. If you previously applied Timeline templates to these rules, they will be overwritten or (if you select 'None') reset to none.`
          );
          selectTimelineTemplate(timelineTemplateName);

          submitBulkEditForm();
          waitForBulkEditActionToFinish({ updatedCount: rows.length });

          // check if timeline template has been updated to selected one
          goToRuleDetailsOf(RULE_NAME);
          getDetails(TIMELINE_TEMPLATE_DETAILS).should('have.text', timelineTemplateName);
        });
      });

      it('Reset timeline template to None', () => {
        getRulesManagementTableRows().then((rows) => {
          const noneTimelineTemplate = 'None';

          selectAllRules();

          // open Timeline template form, submit form without picking timeline template as None is selected by default
          clickApplyTimelineTemplatesMenuItem();

          submitBulkEditForm();
          waitForBulkEditActionToFinish({ updatedCount: rows.length });

          // check if timeline template has been updated to selected one, by opening rule that have had timeline prior to editing
          goToRuleDetailsOf(RULE_NAME);
          getDetails(TIMELINE_TEMPLATE_DETAILS).should('have.text', noneTimelineTemplate);
        });
      });
    });

    describe('Schedule', () => {
      it('Default values are applied to bulk edit schedule fields', () => {
        getRulesManagementTableRows().then((rows) => {
          selectAllRules();
          clickUpdateScheduleMenuItem();

          assertUpdateScheduleWarningExists(rows.length);

          assertDefaultValuesAreAppliedToScheduleFields({
            interval: 5,
            lookback: 1,
          });
        });
      });

      it('Updates schedule', () => {
        getRulesManagementTableRows().then((rows) => {
          selectAllRules();
          clickUpdateScheduleMenuItem();

          assertUpdateScheduleWarningExists(rows.length);

          typeScheduleInterval('20');
          setScheduleIntervalTimeUnit('Hours');

          typeScheduleLookback('10');
          setScheduleLookbackTimeUnit('Minutes');

          submitBulkEditForm();
          waitForBulkEditActionToFinish({ updatedCount: rows.length });

          goToRuleDetailsOf(RULE_NAME);

          assertRuleScheduleValues({
            interval: '20h',
            lookback: '10m',
          });
        });
      });

      it('Validates invalid inputs when scheduling', () => {
        getRulesManagementTableRows().then((rows) => {
          selectAllRules();
          clickUpdateScheduleMenuItem();

          // Validate invalid values are corrected to minimumValue - for 0 and negative values
          typeScheduleInterval('0');
          setScheduleIntervalTimeUnit('Hours');

          typeScheduleLookback('-5');
          setScheduleLookbackTimeUnit('Seconds');

          submitBulkEditForm();
          waitForBulkEditActionToFinish({ updatedCount: rows.length });

          goToRuleDetailsOf(RULE_NAME);

          assertRuleScheduleValues({
            interval: '1h',
            lookback: '1s',
          });
        });
      });
    });
  }
);

// ES|QL rule type is supported  only in ESS environment
// Adding 2 use cases only for this rule type, while it is disabled on serverless
// Created these limited separate scenarios, is done for purpose not duplicating existing tests with new rule type added only for ESS env
// as they will fail when enabled on serverless
// Having 2 sets of complete scenarios for both envs would have a high maintenance cost
// When ES|QL enabled on serverless this rule type can be added to complete set of tests, with minimal changes to tests itself (adding creation of new rule, change number of expected rules, etc)
describe('Detection rules, bulk edit, ES|QL rule type', { tags: ['@ess'] }, () => {
  beforeEach(() => {
    login();
    preventPrebuiltRulesPackageInstallation(); // Make sure prebuilt rules aren't pulled from Fleet API
    // Make sure persisted rules table state is cleared
    resetRulesTableState();
    deleteAlertsAndRules();
    createRule(
      getEsqlRule({
        tags: ['test-default-tag-1', 'test-default-tag-2'],
        enabled: false,
      })
    );
    visitRulesManagementTable();
    disableAutoRefresh();
  });

  describe('Tags actions', () => {
    // ensures bulk edit action is applied to the rule type
    it('Add tags to ES|QL rule', { tags: ['@ess'] }, () => {
      getRulesManagementTableRows().then((rows) => {
        const tagsToBeAdded = ['tag-to-add-1', 'tag-to-add-2'];
        const resultingTags = [...prePopulatedTags, ...tagsToBeAdded];

        // check if only pre-populated tags exist in the tags filter
        checkTagsInTagsFilter(prePopulatedTags, EUI_SELECTABLE_LIST_ITEM_SR_TEXT);

        selectAllRules();

        // open add tags form and add 2 new tags
        openBulkEditAddTagsForm();
        typeTags(tagsToBeAdded);
        submitBulkEditForm();
        waitForBulkEditActionToFinish({ updatedCount: rows.length });

        // check if all rules have been updated with new tags
        testAllTagsBadges(resultingTags);

        // check that new tags were added to tags filter
        // tags in tags filter sorted alphabetically
        const resultingTagsInFilter = [...resultingTags].sort();
        checkTagsInTagsFilter(resultingTagsInFilter, EUI_SELECTABLE_LIST_ITEM_SR_TEXT);
      });
    });
  });

  describe('Index patterns', () => {
    it(
      'Index pattern action applied to ES|QL rules, user cancels action',
      { tags: ['@ess'] },
      () => {
        selectAllRules();
        clickAddIndexPatternsMenuItem();

        // confirm editing all rules, that are not Machine Learning
        checkEsqlRulesCannotBeModified(1);

        // user cancels action and modal disappears
        cancelConfirmationModal();
      }
    );
  });
});
