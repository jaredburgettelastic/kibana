/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import {
  CanLockHoverActions,
  HasParentApi,
  HasUniqueId,
  PublishesBlockingError,
  PublishesDataLoading,
  PublishesDisabledActionIds,
  PublishesDescription,
  PublishesTitle,
} from '@kbn/presentation-publishing';
import { UiActionsService } from '@kbn/ui-actions-plugin/public';
import { MaybePromise } from '@kbn/utility-types';

/** ------------------------------------------------------------------------------------------
 * Panel Types
 * ------------------------------------------------------------------------------------------ */
export type PanelCompatibleComponent<
  ApiType extends DefaultPresentationPanelApi = DefaultPresentationPanelApi,
  PropsType extends {} = {}
> = React.ForwardRefExoticComponent<PropsType & React.RefAttributes<ApiType>>;

export interface PresentationPanelInternalProps<
  ApiType extends DefaultPresentationPanelApi = DefaultPresentationPanelApi,
  PropsType extends {} = {}
> {
  Component: PanelCompatibleComponent<ApiType, PropsType>;
  componentProps?: Omit<React.ComponentProps<PanelCompatibleComponent<ApiType, PropsType>>, 'ref'>;

  showShadow?: boolean;
  showBorder?: boolean;
  showBadges?: boolean;
  showNotifications?: boolean;

  /**
   * Set to true to not show PanelLoader component while Panel is loading
   */
  hideLoader?: boolean;
  hideHeader?: boolean;
  hideInspector?: boolean;

  // TODO remove these in favour of a more generic action management system
  actionPredicate?: (actionId: string) => boolean;
  getActions?: UiActionsService['getTriggerCompatibleActions'];

  /**
   * Ordinal number of the embeddable in the container, used as a
   * "title" when the panel has no title, i.e. "Panel {index}".
   */
  index?: number;

  /**
   * Set the drag handlers to be used by kbn-grid-layout
   * Note: If we make kbn-grid-layout responsible for **all** panel placement
   *       logic, then this could be removed.
   */
  setDragHandles?: (refs: Array<HTMLElement | null>) => void;
}

/**
 * The API that any component passed to the `Component` prop of `PresentationPanel` should implement.
 * Everything in this API is Partial because it is valid for a component to implement none of these methods.
 */
export interface DefaultPresentationPanelApi
  extends HasUniqueId,
    Partial<
      PublishesTitle &
        PublishesDataLoading &
        PublishesBlockingError &
        PublishesDescription &
        PublishesDisabledActionIds &
        HasParentApi &
        CanLockHoverActions
    > {}

export type PresentationPanelProps<
  ApiType extends DefaultPresentationPanelApi = DefaultPresentationPanelApi,
  PropsType extends {} = {}
> = Omit<PresentationPanelInternalProps<ApiType, PropsType>, 'Component'> & {
  Component: MaybePromise<PanelCompatibleComponent<ApiType, PropsType> | null>;
};
