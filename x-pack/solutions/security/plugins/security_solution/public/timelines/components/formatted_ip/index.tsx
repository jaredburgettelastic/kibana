/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { isArray, isEmpty, isString, uniq } from 'lodash/fp';
import type { ComponentProps } from 'react';
import React, { useCallback, useMemo, useContext } from 'react';
import deepEqual from 'fast-deep-equal';

import type { EuiButtonEmpty, EuiButtonIcon } from '@elastic/eui';
import { useExpandableFlyoutApi } from '@kbn/expandable-flyout';
import { StatefulEventContext } from '../../../common/components/events_viewer/stateful_event_context';
import { FlowTargetSourceDest } from '../../../../common/search_strategy/security_solution/network';
import {
  DragEffects,
  DraggableWrapper,
} from '../../../common/components/drag_and_drop/draggable_wrapper';
import { escapeDataProviderId } from '../../../common/components/drag_and_drop/helpers';
import { getOrEmptyTagFromValue } from '../../../common/components/empty_value';
import { parseQueryValue } from '../timeline/body/renderers/parse_query_value';
import type { DataProvider } from '../timeline/data_providers/data_provider';
import { IS_OPERATOR } from '../timeline/data_providers/data_provider';
import { Provider } from '../timeline/data_providers/provider';
import { NetworkDetailsLink } from '../../../common/components/links';
import { NetworkPanelKey } from '../../../flyout/network_details';

const getUniqueId = ({
  contextId,
  eventId,
  fieldName,
  address,
}: {
  contextId: string;
  eventId: string;
  fieldName: string;
  address: string | object | null | undefined;
}) => `formatted-ip-data-provider-${contextId}-${fieldName}-${address}-${eventId}`;

const tryStringify = (value: string | object | null | undefined): string => {
  try {
    return JSON.stringify(value);
  } catch (_) {
    return `${value}`;
  }
};

const getDataProvider = ({
  contextId,
  eventId,
  fieldName,
  address,
}: {
  contextId: string;
  eventId: string;
  fieldName: string;
  address: string | object | null | undefined;
}): DataProvider => ({
  enabled: true,
  id: escapeDataProviderId(getUniqueId({ contextId, eventId, fieldName, address })),
  name: `${fieldName}: ${parseQueryValue(address)}`,
  queryMatch: {
    field: fieldName,
    value: parseQueryValue(address),
    operator: IS_OPERATOR,
  },
  excluded: false,
  kqlQuery: '',
  and: [],
});

const NonDecoratedIpComponent: React.FC<{
  contextId: string;
  eventId: string;
  fieldName: string;
  fieldType: string;
  isAggregatable: boolean;
  isDraggable: boolean;
  truncate?: boolean;
  value: string | object | null | undefined;
}> = ({
  contextId,
  eventId,
  fieldName,
  fieldType,
  isAggregatable,
  isDraggable,
  truncate,
  value,
}) => {
  const key = useMemo(
    () =>
      `non-decorated-ip-draggable-wrapper-${getUniqueId({
        contextId,
        eventId,
        fieldName,
        address: value,
      })}`,
    [contextId, eventId, fieldName, value]
  );

  const dataProviderProp = useMemo(
    () => getDataProvider({ contextId, eventId, fieldName, address: value }),
    [contextId, eventId, fieldName, value]
  );

  const content = useMemo(
    () =>
      typeof value !== 'object'
        ? getOrEmptyTagFromValue(value)
        : getOrEmptyTagFromValue(tryStringify(value)),
    [value]
  );

  const render: ComponentProps<typeof DraggableWrapper>['render'] = useCallback(
    (dataProvider: DataProvider, _, snapshot) =>
      snapshot.isDragging ? (
        <DragEffects>
          <Provider dataProvider={dataProvider} />
        </DragEffects>
      ) : (
        content
      ),
    [content]
  );

  if (!isDraggable) {
    return content;
  }

  return (
    <DraggableWrapper
      dataProvider={dataProviderProp}
      fieldType={fieldType}
      isAggregatable={isAggregatable}
      isDraggable={isDraggable}
      key={key}
      render={render}
      truncate={truncate}
    />
  );
};

const NonDecoratedIp = React.memo(NonDecoratedIpComponent);

interface AddressLinksItemProps extends Omit<AddressLinksProps, 'addresses'> {
  address: string;
}

const AddressLinksItemComponent: React.FC<AddressLinksItemProps> = ({
  address,
  Component,
  contextId,
  eventId,
  fieldName,
  fieldType,
  isAggregatable,
  isButton,
  isDraggable,
  onClick,
  truncate,
  title,
}) => {
  const { openFlyout } = useExpandableFlyoutApi();

  const key = `address-links-draggable-wrapper-${getUniqueId({
    contextId,
    eventId,
    fieldName,
    address,
  })}`;

  const dataProviderProp = useMemo(
    () => getDataProvider({ contextId, eventId, fieldName, address }),
    [address, contextId, eventId, fieldName]
  );

  const eventContext = useContext(StatefulEventContext);
  const isInTimelineContext =
    address && eventContext?.enableIpDetailsFlyout && eventContext?.timelineID;

  const openNetworkDetailsSidePanel = useCallback(
    (ip: string) => {
      if (onClick) {
        onClick();
      }

      if (eventContext && isInTimelineContext) {
        openFlyout({
          right: {
            id: NetworkPanelKey,
            params: {
              ip,
              scopeId: eventContext.timelineID,
              flowTarget: fieldName.includes(FlowTargetSourceDest.destination)
                ? FlowTargetSourceDest.destination
                : FlowTargetSourceDest.source,
            },
          },
        });
      }
    },
    [onClick, eventContext, isInTimelineContext, fieldName, openFlyout]
  );

  // The below is explicitly defined this way as the onClick takes precedence when it and the href are both defined
  // When this component is used outside of timeline/alerts table (i.e. in the flyout) we would still like it to link to the IP Overview page
  const content = useMemo(
    () =>
      Component ? (
        <NetworkDetailsLink
          Component={Component}
          ip={address}
          isButton={isButton}
          onClick={isInTimelineContext ? openNetworkDetailsSidePanel : undefined}
          title={title}
        />
      ) : (
        <NetworkDetailsLink
          Component={Component}
          ip={address}
          isButton={isButton}
          onClick={isInTimelineContext ? openNetworkDetailsSidePanel : undefined}
          title={title}
        />
      ),
    [Component, address, isButton, isInTimelineContext, openNetworkDetailsSidePanel, title]
  );

  const render: ComponentProps<typeof DraggableWrapper>['render'] = useCallback(
    (_props, _provided, snapshot) =>
      snapshot.isDragging ? (
        <DragEffects>
          <Provider dataProvider={dataProviderProp} />
        </DragEffects>
      ) : (
        content
      ),
    [dataProviderProp, content]
  );

  if (!isDraggable) {
    return content;
  }

  return (
    <DraggableWrapper
      dataProvider={dataProviderProp}
      isDraggable={isDraggable}
      fieldType={fieldType}
      isAggregatable={isAggregatable}
      key={key}
      render={render}
      truncate={truncate}
    />
  );
};

const AddressLinksItem = React.memo(AddressLinksItemComponent);

interface AddressLinksProps {
  addresses: string[];
  Component?: typeof EuiButtonEmpty | typeof EuiButtonIcon;
  contextId: string;
  eventId: string;
  fieldName: string;
  fieldType: string;
  isAggregatable: boolean;
  isButton?: boolean;
  isDraggable: boolean;
  onClick?: () => void;
  truncate?: boolean;
  title?: string;
}

const AddressLinksComponent: React.FC<AddressLinksProps> = ({
  addresses,
  Component,
  contextId,
  eventId,
  fieldName,
  fieldType,
  isAggregatable,
  isButton,
  isDraggable,
  onClick,
  truncate,
  title,
}) => {
  const uniqAddresses = useMemo(() => uniq(addresses), [addresses]);

  const content = useMemo(
    () =>
      uniqAddresses.map((address) => (
        <AddressLinksItem
          key={address}
          address={address}
          Component={Component}
          contextId={contextId}
          eventId={eventId}
          fieldName={fieldName}
          fieldType={fieldType}
          isAggregatable={isAggregatable}
          isButton={isButton}
          isDraggable={isDraggable}
          onClick={onClick}
          truncate={truncate}
          title={title}
        />
      )),
    [
      Component,
      contextId,
      eventId,
      fieldName,
      fieldType,
      isAggregatable,
      isButton,
      isDraggable,
      onClick,
      title,
      truncate,
      uniqAddresses,
    ]
  );

  return <>{content}</>;
};

const AddressLinks = React.memo(
  AddressLinksComponent,
  (prevProps, nextProps) =>
    prevProps.contextId === nextProps.contextId &&
    prevProps.eventId === nextProps.eventId &&
    prevProps.fieldName === nextProps.fieldName &&
    prevProps.isAggregatable === nextProps.isAggregatable &&
    prevProps.fieldType === nextProps.fieldType &&
    prevProps.isDraggable === nextProps.isDraggable &&
    prevProps.truncate === nextProps.truncate &&
    deepEqual(prevProps.addresses, nextProps.addresses)
);

const FormattedIpComponent: React.FC<{
  Component?: typeof EuiButtonEmpty | typeof EuiButtonIcon;
  contextId: string;
  eventId: string;
  fieldName: string;
  fieldType: string;
  isAggregatable: boolean;
  isButton?: boolean;
  isDraggable: boolean;
  onClick?: () => void;
  title?: string;
  truncate?: boolean;
  value: string | object | null | undefined;
}> = ({
  Component,
  contextId,
  eventId,
  fieldName,
  fieldType,
  isAggregatable,
  isDraggable,
  isButton,
  onClick,
  title,
  truncate,
  value,
}) => {
  if (isString(value) && !isEmpty(value)) {
    try {
      const addresses = JSON.parse(value);
      if (isArray(addresses)) {
        return (
          <AddressLinks
            addresses={addresses}
            Component={Component}
            contextId={contextId}
            eventId={eventId}
            fieldName={fieldName}
            fieldType={fieldType}
            isAggregatable={isAggregatable}
            isButton={isButton}
            isDraggable={isDraggable}
            onClick={onClick}
            title={title}
            truncate={truncate}
          />
        );
      }
    } catch (_) {
      // fall back to formatting it as a single link
    }

    // return a single draggable link
    return (
      <AddressLinks
        addresses={[value]}
        Component={Component}
        contextId={contextId}
        eventId={eventId}
        isButton={isButton}
        isDraggable={isDraggable}
        onClick={onClick}
        fieldName={fieldName}
        fieldType={fieldType}
        isAggregatable={isAggregatable}
        truncate={truncate}
        title={title}
      />
    );
  } else {
    return (
      <NonDecoratedIp
        contextId={contextId}
        eventId={eventId}
        fieldName={fieldName}
        fieldType={fieldType}
        isAggregatable={isAggregatable}
        isDraggable={isDraggable}
        truncate={truncate}
        value={value}
      />
    );
  }
};

export const FormattedIp = React.memo(
  FormattedIpComponent,
  (prevProps, nextProps) =>
    prevProps.contextId === nextProps.contextId &&
    prevProps.eventId === nextProps.eventId &&
    prevProps.fieldName === nextProps.fieldName &&
    prevProps.isAggregatable === nextProps.isAggregatable &&
    prevProps.fieldType === nextProps.fieldType &&
    prevProps.isDraggable === nextProps.isDraggable &&
    prevProps.truncate === nextProps.truncate &&
    deepEqual(prevProps.value, nextProps.value)
);
