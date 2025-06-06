/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { waitForEuiPopoverOpen } from '@elastic/eui/lib/test/rtl';
import { chartPluginMock } from '@kbn/charts-plugin/public/mocks';
import { usePerformanceContext } from '@kbn/ebt-tools';
import { observabilityAIAssistantPluginMock } from '@kbn/observability-ai-assistant-plugin/public/mock';
import { HeaderMenuPortal, TagsList } from '@kbn/observability-shared-plugin/public';
import { encode } from '@kbn/rison';
import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import React from 'react';
import Router from 'react-router-dom';
import { paths } from '../../../common/locators/paths';
import { historicalSummaryData } from '../../data/slo/historical_summary_data';
import { emptySloList, sloList } from '../../data/slo/slo';
import { useCreateDataView } from '../../hooks/use_create_data_view';
import { useCreateSlo } from '../../hooks/use_create_slo';
import { useDeleteSlo } from '../../hooks/use_delete_slo';
import { useDeleteSloInstance } from '../../hooks/use_delete_slo_instance';
import { useFetchHistoricalSummary } from '../../hooks/use_fetch_historical_summary';
import { useFetchSloList } from '../../hooks/use_fetch_slo_list';
import { useLicense } from '../../hooks/use_license';
import { usePermissions } from '../../hooks/use_permissions';
import { useKibana } from '../../hooks/use_kibana';
import { render } from '../../utils/test_helper';
import { useGetSettings } from '../slo_settings/hooks/use_get_settings';
import { SlosPage } from './slos';

jest.mock('react-router-dom', () => ({
  ...jest.requireActual('react-router-dom'),
  useParams: jest.fn(),
}));

jest.mock('@kbn/observability-shared-plugin/public');
jest.mock('../../hooks/use_kibana');
jest.mock('../../hooks/use_license');
jest.mock('../../hooks/use_fetch_slo_list');
jest.mock('../../hooks/use_create_slo');
jest.mock('../slo_settings/hooks/use_get_settings');
jest.mock('../../hooks/use_delete_slo');
jest.mock('../../hooks/use_delete_slo_instance');
jest.mock('../../hooks/use_fetch_historical_summary');
jest.mock('../../hooks/use_permissions');
jest.mock('../../hooks/use_create_data_view');
jest.mock('@kbn/ebt-tools');

const useGetSettingsMock = useGetSettings as jest.Mock;
const useKibanaMock = useKibana as jest.Mock;
const useLicenseMock = useLicense as jest.Mock;
const useFetchSloListMock = useFetchSloList as jest.Mock;
const useCreateSloMock = useCreateSlo as jest.Mock;
const useDeleteSloMock = useDeleteSlo as jest.Mock;
const useDeleteSloInstanceMock = useDeleteSloInstance as jest.Mock;
const useFetchHistoricalSummaryMock = useFetchHistoricalSummary as jest.Mock;
const usePermissionsMock = usePermissions as jest.Mock;
const useCreateDataViewMock = useCreateDataView as jest.Mock;
const TagsListMock = TagsList as jest.Mock;
const usePerformanceContextMock = usePerformanceContext as jest.Mock;

usePerformanceContextMock.mockReturnValue({ onPageReady: jest.fn() });
TagsListMock.mockReturnValue(<div>Tags list</div>);
const HeaderMenuPortalMock = HeaderMenuPortal as jest.Mock;
HeaderMenuPortalMock.mockReturnValue(<div>Portal node</div>);

const mockCreateSlo = jest.fn();
const mockDeleteSlo = jest.fn();
const mockDeleteInstance = jest.fn();

useCreateSloMock.mockReturnValue({ mutate: mockCreateSlo });
useDeleteSloMock.mockReturnValue({ mutate: mockDeleteSlo });
useDeleteSloInstanceMock.mockReturnValue({ mutate: mockDeleteInstance });
useCreateDataViewMock.mockReturnValue({});

const mockNavigate = jest.fn();
const mockAddSuccess = jest.fn();
const mockAddError = jest.fn();
const mockLocator = jest.fn();

jest.mock('@kbn/response-ops-rule-form/flyout', () => ({
  RuleFormFlyout: jest.fn(() => <div data-test-subj="add-rule-flyout">Add rule flyout</div>),
}));

const mockKibana = () => {
  useKibanaMock.mockReturnValue({
    services: {
      theme: {},
      application: { navigateToUrl: mockNavigate },
      charts: chartPluginMock.createSetupContract(),
      data: {
        dataViews: {
          find: jest.fn().mockReturnValue([]),
          get: jest.fn().mockReturnValue([]),
        },
      },
      dataViews: {
        create: jest.fn().mockResolvedValue(42),
      },
      docLinks: {
        links: {
          query: {},
          observability: {
            slo: 'dummy_link',
          },
        },
      },
      http: {
        basePath: {
          prepend: (url: string) => url,
        },
      },
      notifications: {
        toasts: {
          addSuccess: mockAddSuccess,
          addError: mockAddError,
        },
      },
      observabilityAIAssistant: observabilityAIAssistantPluginMock.createStartContract(),
      share: {
        url: {
          locators: {
            get: mockLocator,
          },
        },
      },
      storage: {
        get: () => {},
      },
      triggersActionsUi: {},
      uiSettings: {
        get: (settings: string) => {
          if (settings === 'dateFormat') return 'YYYY-MM-DD';
          if (settings === 'format:percent:defaultPattern') return '0.0%';
          return '';
        },
      },
      unifiedSearch: {
        ui: {
          SearchBar: () => <div>SearchBar</div>,
          QueryStringInput: () => <div>Query String Input</div>,
        },
        autocomplete: {
          hasQuerySuggestions: () => {},
        },
      },
      executionContext: {
        get: () => ({
          name: 'slo',
        }),
      },
    },
  });
};

describe('SLOs Page', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockKibana();
    useGetSettingsMock.mockReturnValue({
      isLoading: false,
      data: {
        useAllRemoteClusters: false,
        selectedRemoteClusters: [],
      },
    });
    usePermissionsMock.mockReturnValue({
      isLoading: false,
      data: { hasAllReadRequested: true, hasAllWriteRequested: true },
    });
    jest
      .spyOn(Router, 'useLocation')
      .mockReturnValue({ pathname: '/slos', search: '', state: '', hash: '' });
    jest
      .spyOn(Router, 'useRouteMatch')
      .mockReturnValue({ url: '/slos', path: '/slos', isExact: true, params: {} });
  });

  describe('when the incorrect license is found', () => {
    beforeEach(() => {
      useFetchSloListMock.mockReturnValue({ isLoading: false, sloList: emptySloList });
      useLicenseMock.mockReturnValue({ hasAtLeast: () => false });
      useFetchHistoricalSummaryMock.mockReturnValue({
        isLoading: false,
        data: {},
      });
    });

    it('navigates to the SLOs Welcome Page', async () => {
      await act(async () => {
        render(<SlosPage />);
      });

      await waitFor(() => {
        expect(mockNavigate).toBeCalledWith(paths.slosWelcome);
      });
    });
  });

  describe('when the correct license is found', () => {
    beforeEach(() => {
      useLicenseMock.mockReturnValue({ hasAtLeast: () => true });
    });

    it('navigates to the SLOs Welcome Page when the API has finished loading and there are no results', async () => {
      useFetchSloListMock.mockReturnValue({ isLoading: false, data: emptySloList });
      useFetchHistoricalSummaryMock.mockReturnValue({
        isLoading: false,
        data: {},
      });

      await act(async () => {
        render(<SlosPage />);
      });

      await waitFor(() => {
        expect(mockNavigate).toBeCalledWith(paths.slosWelcome);
      });
    });

    it('navigates to the SLOs Welcome Page when the user has not the request read permissions', async () => {
      useFetchSloListMock.mockReturnValue({ isLoading: false, data: sloList });
      useFetchHistoricalSummaryMock.mockReturnValue({
        isLoading: false,
        data: historicalSummaryData,
      });
      usePermissionsMock.mockReturnValue({
        isLoading: false,
        data: { hasAllReadRequested: false, hasAllWriteRequested: false },
      });

      await act(async () => {
        render(<SlosPage />);
      });

      await waitFor(() => {
        expect(mockNavigate).toBeCalledWith(paths.slosWelcome);
      });
    });

    it('should have a create new SLO button', async () => {
      useFetchSloListMock.mockReturnValue({ isLoading: false, data: sloList });
      useFetchHistoricalSummaryMock.mockReturnValue({
        isLoading: false,
        data: historicalSummaryData,
      });

      await act(async () => {
        render(<SlosPage />);
      });

      expect(screen.getByText('Create SLO')).toBeTruthy();
    });

    describe('when API has returned results', () => {
      it('renders the SLO list with SLO items', async () => {
        useFetchSloListMock.mockReturnValue({ isLoading: false, data: sloList });

        useFetchHistoricalSummaryMock.mockReturnValue({
          isLoading: false,
          data: historicalSummaryData,
        });

        await act(async () => {
          render(<SlosPage />);
        });
        expect(await screen.findByTestId('sloListViewButton')).toBeTruthy();

        fireEvent.click(screen.getByTestId('sloListViewButton'));

        expect(screen.queryByTestId('slosPage')).toBeTruthy();
        expect(screen.queryByTestId('sloList')).toBeTruthy();
        expect(screen.queryAllByTestId('sloItem')).toBeTruthy();
        expect((await screen.findAllByTestId('sloItem')).length).toBe(sloList.results.length);
      });

      it('allows editing an SLO', async () => {
        useFetchSloListMock.mockReturnValue({ isLoading: false, data: sloList });

        useFetchHistoricalSummaryMock.mockReturnValue({
          isLoading: false,
          data: historicalSummaryData,
        });

        await act(async () => {
          render(<SlosPage />);
        });
        expect(await screen.findByTestId('compactView')).toBeTruthy();
        fireEvent.click(screen.getByTestId('compactView'));

        (await screen.findByLabelText('All actions, row 1')).click();

        await waitForEuiPopoverOpen();

        const button = screen.getByTestId('sloActionsEdit');

        expect(button).toBeTruthy();

        button.click();

        expect(mockNavigate).toBeCalledWith(`${paths.sloEdit(sloList.results.at(0)?.id || '')}`);
      });

      it('allows creating a new rule for an SLO', async () => {
        useFetchSloListMock.mockReturnValue({ isLoading: false, data: sloList });

        useFetchHistoricalSummaryMock.mockReturnValue({
          isLoading: false,
          data: historicalSummaryData,
        });

        await act(async () => {
          render(<SlosPage />);
        });
        expect(await screen.findByTestId('compactView')).toBeTruthy();
        fireEvent.click(screen.getByTestId('compactView'));
        screen.getByLabelText('All actions, row 1').click();

        await waitForEuiPopoverOpen();

        const button = screen.getByTestId('sloActionsCreateRule');

        expect(button).toBeTruthy();

        act(() => {
          button.click();
        });

        expect(screen.getByTestId('add-rule-flyout')).toBeInTheDocument();
      });

      it('allows managing rules for an SLO', async () => {
        useFetchSloListMock.mockReturnValue({ isLoading: false, data: sloList });

        useFetchHistoricalSummaryMock.mockReturnValue({
          isLoading: false,
          data: historicalSummaryData,
        });

        await act(async () => {
          render(<SlosPage />);
        });
        expect(await screen.findByTestId('compactView')).toBeTruthy();
        fireEvent.click(screen.getByTestId('compactView'));
        screen.getByLabelText('All actions, row 1').click();

        await waitForEuiPopoverOpen();

        const button = screen.getByTestId('sloActionsManageRules');

        expect(button).toBeTruthy();

        button.click();

        expect(mockLocator).toBeCalled();
      });

      it('allows deleting an SLO', async () => {
        useFetchSloListMock.mockReturnValue({ isLoading: false, data: sloList });

        useFetchHistoricalSummaryMock.mockReturnValue({
          isLoading: false,
          data: historicalSummaryData,
        });

        await act(async () => {
          render(<SlosPage />);
        });

        expect(await screen.findByTestId('compactView')).toBeTruthy();
        fireEvent.click(screen.getByTestId('compactView'));
        screen.getByLabelText('All actions, row 1').click();

        await waitForEuiPopoverOpen();

        const button = screen.getByTestId('sloActionsDelete');

        expect(button).toBeTruthy();

        act(() => {
          button.click();
        });

        screen.getByTestId('observabilitySolutionSloDeleteModalConfirmButton').click();

        expect(mockDeleteSlo).toBeCalledWith({
          id: sloList.results.at(0)?.id,
          name: sloList.results.at(0)?.name,
        });
      });

      it('allows cloning an SLO', async () => {
        useFetchSloListMock.mockReturnValue({ isLoading: false, data: sloList });

        useFetchHistoricalSummaryMock.mockReturnValue({
          isLoading: false,
          data: historicalSummaryData,
        });

        await act(async () => {
          render(<SlosPage />);
        });

        expect(await screen.findByTestId('compactView')).toBeTruthy();
        fireEvent.click(screen.getByTestId('compactView'));
        screen.getByLabelText('All actions, row 1').click();

        await waitForEuiPopoverOpen();

        const button = screen.getByTestId('sloActionsClone');

        expect(button).toBeTruthy();

        button.click();

        await waitFor(() => {
          const slo = sloList.results.at(0);
          expect(mockNavigate).toBeCalledWith(
            paths.sloCreateWithEncodedForm(
              encode({ ...slo, name: `[Copy] ${slo!.name}`, id: undefined })
            )
          );
        });
      });
    });
  });
});
