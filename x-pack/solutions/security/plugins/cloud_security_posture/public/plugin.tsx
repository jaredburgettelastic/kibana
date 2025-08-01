/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
import React, { lazy, Suspense } from 'react';
import type { CoreSetup, CoreStart, Plugin, PluginInitializerContext } from '@kbn/core/public';
import { KibanaContextProvider } from '@kbn/kibana-react-plugin/public';
import { Storage } from '@kbn/kibana-utils-plugin/public';
import { RedirectAppLinks } from '@kbn/shared-ux-link-redirect-app';
import type {
  CspClientPluginStartDeps,
  FindingMisconfigurationFlyoutFooterProps,
  FindingsMisconfigurationFlyoutContentProps,
  FindingsMisconfigurationFlyoutHeaderProps,
  FindingsVulnerabilityFlyoutContentProps,
  FindingsVulnerabilityFlyoutFooterProps,
  FindingsVulnerabilityFlyoutHeaderProps,
  FindingsMisconfigurationPanelExpandableFlyoutProps,
  FindingsVulnerabilityPanelExpandableFlyoutProps,
} from '@kbn/cloud-security-posture';
import { uiMetricService } from '@kbn/cloud-security-posture-common/utils/ui_metrics';
import { CspLoadingState } from './components/csp_loading_state';
import type { CspRouterProps } from './application/csp_router';
import type { CspClientPluginSetup, CspClientPluginStart, CspClientPluginSetupDeps } from './types';
import { CLOUD_SECURITY_POSTURE_PACKAGE_NAME } from '../common/constants';
import { SetupContext } from './application/setup_context';
import {
  type CSPUIConfigType,
  type ExperimentalFeatures,
  parseExperimentalConfigValue,
} from '../common/experimental_features';
import { ExperimentalFeaturesService } from './common/experimental_features_service';

const LazyCspPolicyTemplateForm = lazy(
  () => import('./components/fleet_extensions/policy_template_form')
);

const LazyCspCustomAssets = lazy(
  () => import('./components/fleet_extensions/custom_assets_extension')
);

// Misconfiguration Flyout Components
export const LazyCspFindingsMisconfigurationFlyout = lazy(
  () => import('./pages/configurations/findings_flyout/findings_flyout')
);
export const LazyCspFindingsMisconfigurationFlyoutHeader = lazy(
  () => import('./pages/configurations/findings_flyout/findings_right/header')
);
export const LazyCspFindingsMisconfigurationFlyoutBody = lazy(
  () => import('./pages/configurations/findings_flyout/findings_right/content')
);
export const LazyCspFindingsMisconfigurationFlyoutFooter = lazy(
  () => import('./pages/configurations/findings_flyout/findings_right/footer')
);

// Vulnerability Flyout Components
export const LazyCspFindingsVulnerabilityFlyout = lazy(
  () =>
    import('./pages/vulnerabilities/vulnerabilities_finding_flyout/vulnerability_finding_flyout')
);
export const LazyCspFindingsVulnerabilityFlyoutHeader = lazy(
  () =>
    import(
      './pages/vulnerabilities/vulnerabilities_finding_flyout/vulnerability_finding_right/header'
    )
);
export const LazyCspFindingsVulnerabilityFlyoutBody = lazy(
  () =>
    import(
      './pages/vulnerabilities/vulnerabilities_finding_flyout/vulnerability_finding_right/content'
    )
);
export const LazyCspFindingsVulnerabilityFlyoutFooter = lazy(
  () =>
    import(
      './pages/vulnerabilities/vulnerabilities_finding_flyout/vulnerability_finding_right/footer'
    )
);

const CspRouterLazy = lazy(() => import('./application/csp_router'));
const CspRouter = (props: CspRouterProps) => (
  <Suspense fallback={<CspLoadingState />}>
    <CspRouterLazy {...props} />
  </Suspense>
);

export class CspPlugin
  implements
    Plugin<
      CspClientPluginSetup,
      CspClientPluginStart,
      CspClientPluginSetupDeps,
      CspClientPluginStartDeps
    >
{
  private isCloudEnabled?: boolean;
  private config: CSPUIConfigType;
  private experimentalFeatures: ExperimentalFeatures;

  constructor(private readonly initializerContext: PluginInitializerContext) {
    this.config = this.initializerContext.config.get<CSPUIConfigType>();

    this.experimentalFeatures = parseExperimentalConfigValue(
      this.config.enableExperimental || []
    )?.features;
  }

  public setup(
    _core: CoreSetup<CspClientPluginStartDeps, CspClientPluginStart>,
    plugins: CspClientPluginSetupDeps
  ): CspClientPluginSetup {
    this.isCloudEnabled = plugins.cloud.isCloudEnabled;
    if (plugins.usageCollection) uiMetricService.setup(plugins.usageCollection);

    // Return methods that should be available to other plugins
    return {};
  }

  public start(core: CoreStart, plugins: CspClientPluginStartDeps): CspClientPluginStart {
    ExperimentalFeaturesService.init({ experimentalFeatures: this.experimentalFeatures });
    plugins.fleet.registerExtension({
      package: CLOUD_SECURITY_POSTURE_PACKAGE_NAME,
      view: 'package-policy-replace-define-step',
      Component: LazyCspPolicyTemplateForm,
    });

    plugins.fleet.registerExtension({
      package: CLOUD_SECURITY_POSTURE_PACKAGE_NAME,
      view: 'package-detail-assets',
      Component: LazyCspCustomAssets,
    });

    const storage = new Storage(localStorage);

    // Keep as constant to prevent remounts https://github.com/elastic/kibana/issues/146773
    const App = (props: CspRouterProps) => (
      <KibanaContextProvider services={{ ...core, ...plugins, storage }}>
        <RedirectAppLinks coreStart={core}>
          <div css={{ width: '100%', height: '100%' }}>
            <SetupContext.Provider value={{ isCloudEnabled: this.isCloudEnabled }}>
              <CspRouter {...props} />
            </SetupContext.Provider>
          </div>
        </RedirectAppLinks>
      </KibanaContextProvider>
    );

    return {
      getCloudSecurityPostureRouter: () => App,
      getCloudSecurityPostureMisconfigurationFlyout: () => {
        return {
          Component: (props: FindingsMisconfigurationPanelExpandableFlyoutProps['params']) => (
            <LazyCspFindingsMisconfigurationFlyout {...props}>
              {props.children}
            </LazyCspFindingsMisconfigurationFlyout>
          ),
          Header: (props: FindingsMisconfigurationFlyoutHeaderProps) => (
            <LazyCspFindingsMisconfigurationFlyoutHeader {...props} />
          ),
          Body: (props: FindingsMisconfigurationFlyoutContentProps) => (
            <LazyCspFindingsMisconfigurationFlyoutBody {...props} />
          ),
          Footer: (props: FindingMisconfigurationFlyoutFooterProps) => (
            <LazyCspFindingsMisconfigurationFlyoutFooter {...props} />
          ),
        };
      },
      getCloudSecurityPostureVulnerabilityFlyout: () => {
        return {
          Component: (props: FindingsVulnerabilityPanelExpandableFlyoutProps['params']) => (
            <LazyCspFindingsVulnerabilityFlyout {...props}>
              {props.children}
            </LazyCspFindingsVulnerabilityFlyout>
          ),
          Header: (props: FindingsVulnerabilityFlyoutHeaderProps) => (
            <LazyCspFindingsVulnerabilityFlyoutHeader {...props} />
          ),
          Body: (props: FindingsVulnerabilityFlyoutContentProps) => (
            <LazyCspFindingsVulnerabilityFlyoutBody {...props} />
          ),
          Footer: (props: FindingsVulnerabilityFlyoutFooterProps) => (
            <LazyCspFindingsVulnerabilityFlyoutFooter {...props} />
          ),
        };
      },
    };
  }

  public stop() {}
}
