/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import { i18n } from '@kbn/i18n';
import { toMountPoint } from '@kbn/react-kibana-mount';
import React from 'react';
import { firstValueFrom } from 'rxjs';
import type { SerializedSearchSourceFields } from '@kbn/data-plugin/common';
import { FormattedMessage, InjectedIntl } from '@kbn/i18n-react';
import { ShareContext, type ExportShare } from '@kbn/share-plugin/public';
import { LocatorParams } from '@kbn/reporting-common/types';
import { getSearchCsvJobParams, CsvSearchModeParams } from '../shared/get_search_csv_job_params';
import type { ExportModalShareOpts } from '.';
import { checkLicense } from '../..';

export const reportingCsvExportProvider = ({
  apiClient,
  application,
  license,
  startServices$,
}: ExportModalShareOpts): ExportShare => {
  const getShareMenuItems = ({
    objectType,
    sharingData,
    toasts,
  }: ShareContext): ReturnType<ExportShare['config']> => {
    const licenseCheck = checkLicense(license.check('reporting', 'basic'));
    const licenseToolTipContent = licenseCheck.message;
    const licenseHasCsvReporting = licenseCheck.showLinks;
    const licenseDisabled = !licenseCheck.enableLinks;

    const capabilityHasCsvReporting = application.capabilities.discover_v2?.generateCsv === true;

    if (!(licenseHasCsvReporting && capabilityHasCsvReporting)) {
      return null;
    }

    const getSearchSource = sharingData.getSearchSource as ({
      addGlobalTimeFilter,
      absoluteTime,
    }: {
      addGlobalTimeFilter?: boolean;
      absoluteTime?: boolean;
    }) => SerializedSearchSourceFields;

    const getSearchModeParams = (forShareUrl?: boolean): CsvSearchModeParams => {
      if (sharingData.isTextBased) {
        // csv v2 uses locator params
        return {
          isEsqlMode: true,
          locatorParams: sharingData.locatorParams as LocatorParams[],
        };
      }

      // csv v1 uses search source and columns
      return {
        isEsqlMode: false,
        columns: sharingData.columns as string[] | undefined,
        searchSource: getSearchSource({
          addGlobalTimeFilter: true,
          absoluteTime: !forShareUrl,
        }),
      };
    };

    const generateReportingJobCSV = ({ intl }: { intl: InjectedIntl }) => {
      const { reportType, decoratedJobParams } = getSearchCsvJobParams({
        apiClient,
        searchModeParams: getSearchModeParams(false),
        title: sharingData.title as string,
      });

      return apiClient
        .createReportingShareJob(reportType, decoratedJobParams)
        .then(() => firstValueFrom(startServices$))
        .then(([startServices]) => {
          toasts.addSuccess({
            title: intl.formatMessage(
              {
                id: 'reporting.share.modalContent.successfullyQueuedReportNotificationTitle',
                defaultMessage: 'Queued report for {objectType}',
              },
              { objectType }
            ),
            text: toMountPoint(
              <FormattedMessage
                id="reporting.share.modalContent.successfullyQueuedReportNotificationDescription"
                defaultMessage="Track its progress in {path}."
                values={{
                  path: (
                    <a href={apiClient.getManagementLink()}>
                      <FormattedMessage
                        id="reporting.share.publicNotifier.reportLink.reportingSectionUrlLinkLabel"
                        defaultMessage="Stack Management &gt; Reporting"
                      />
                    </a>
                  ),
                }}
              />,
              startServices
            ),
            'data-test-subj': 'queueReportSuccess',
          });
        })
        .catch((error) => {
          toasts.addError(error, {
            title: intl.formatMessage({
              id: 'reporting.share.modalContent.notification.reportingErrorTitle',
              defaultMessage: 'Unable to create report',
            }),
            toastMessage: (
              // eslint-disable-next-line react/no-danger
              <span dangerouslySetInnerHTML={{ __html: error.body?.message }} />
            ) as unknown as string,
          });
        });
    };

    const panelTitle = i18n.translate('reporting.share.contextMenu.export.csvReportsButtonLabel', {
      defaultMessage: 'Export',
    });

    const { reportType, decoratedJobParams } = getSearchCsvJobParams({
      apiClient,
      searchModeParams: getSearchModeParams(true),
      title: sharingData.title as string,
    });

    const relativePath = apiClient.getReportingPublicJobPath(reportType, decoratedJobParams);

    const absoluteUrl = new URL(relativePath, window.location.href).toString();

    return {
      name: panelTitle,
      toolTipContent: licenseToolTipContent,
      exportType: reportType,
      label: 'CSV',
      disabled: licenseDisabled,
      generateAssetExport: generateReportingJobCSV,
      generateAssetURIValue: () => absoluteUrl,
      helpText: (
        <FormattedMessage
          id="reporting.share.csv.reporting.helpTextCSV"
          defaultMessage="Export a CSV of this {objectType}."
          values={{ objectType }}
        />
      ),
      generateExportButton: (
        <FormattedMessage
          id="reporting.share.generateButtonLabelCSV"
          data-test-subj="generateReportButton"
          defaultMessage="Generate CSV"
        />
      ),
      renderCopyURIButton: true,
    };
  };

  return {
    shareType: 'integration',
    id: 'csvReportsModal',
    groupId: 'export',
    config: getShareMenuItems,
  };
};
