// Case 03 — SOC lab: Linux gateway (nftables firewall + Suricata IPS inline), Windows endpoint with
// Microsoft Defender for Endpoint, Log Analytics + Microsoft Sentinel with custom Zeek tables,
// data collection rules, a watchlist and four analytics rules loaded from detections/kql/sentinel-rules.
//
// Addressing (fixed, referenced by the gateway's cloud-init and the watchlist):
//   snet-external 10.70.0.0/24  gateway eth0 (public IP, SNAT to the internet)
//   snet-internal 10.70.1.0/24  gateway eth1 10.70.1.4 (IP forwarding)
//   snet-workload 10.70.2.0/24  Windows endpoint 10.70.2.4; default route -> 10.70.1.4

@description('Azure region')
param location string = resourceGroup().location

@description('Name prefix for every resource')
param prefix string = 'nthc'

@description('Admin user name for both virtual machines')
param adminUsername string = 'labadmin'

@description('SSH public key for the gateway (password authentication is disabled)')
param sshPublicKey string

@secure()
@description('Local administrator password for the Windows endpoint')
param windowsAdminPassword string

@description('Object ID of the user who runs the lab; gets permission to upload Zeek logs to the custom tables')
param deployerObjectId string

param gatewayVmSize string = 'Standard_B2s'
param windowsVmSize string = 'Standard_B2s'

@description('Daily auto-shutdown time for both VMs (HHmm, Romance Standard Time)')
param shutdownTime string = '2300'

var gatewayInternalIp = '10.70.1.4'
var windowsIp = '10.70.2.4'
var gatewayName = '${prefix}-gw01'
var windowsName = '${prefix}-win01'
var cloudInit = replace(replace(loadTextContent('gateway-cloud-init.yaml'),
  '__RULES_DNS_B64__', base64(loadTextContent('../../detections/suricata/dns-tunnel.rules'))),
  '__RULES_CS_B64__', base64(loadTextContent('../../detections/suricata/cobalt-strike-profile.rules')))

// ------------------------------------------------------------------------------------------ network

resource nsgExternal 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${prefix}-nsg-external'
  location: location
  properties: {
    securityRules: [] // default rules only: no inbound from the internet; return traffic is stateful
  }
}

resource nsgInternal 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${prefix}-nsg-internal'
  location: location
  properties: {
    securityRules: []
  }
}

resource routeWorkload 'Microsoft.Network/routeTables@2024-05-01' = {
  name: '${prefix}-rt-workload'
  location: location
  properties: {
    disableBgpRoutePropagation: true
    routes: [
      {
        name: 'default-via-gateway'
        properties: {
          addressPrefix: '0.0.0.0/0'
          nextHopType: 'VirtualAppliance'
          nextHopIpAddress: gatewayInternalIp
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${prefix}-vnet'
  location: location
  properties: {
    addressSpace: { addressPrefixes: ['10.70.0.0/16'] }
    subnets: [
      {
        name: 'snet-external'
        properties: { addressPrefix: '10.70.0.0/24', networkSecurityGroup: { id: nsgExternal.id } }
      }
      {
        name: 'snet-internal'
        properties: { addressPrefix: '10.70.1.0/24', networkSecurityGroup: { id: nsgInternal.id } }
      }
      {
        name: 'snet-workload'
        properties: {
          addressPrefix: '10.70.2.0/24'
          networkSecurityGroup: { id: nsgInternal.id }
          routeTable: { id: routeWorkload.id }
        }
      }
    ]
  }
}

resource gatewayPip 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: '${prefix}-pip-gateway'
  location: location
  sku: { name: 'Standard' }
  properties: { publicIPAllocationMethod: 'Static' }
}

resource nicGatewayExternal 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: '${gatewayName}-eth0'
  location: location
  properties: {
    enableIPForwarding: true
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: { id: vnet.properties.subnets[0].id }
          privateIPAllocationMethod: 'Static'
          privateIPAddress: '10.70.0.4'
          publicIPAddress: { id: gatewayPip.id }
        }
      }
    ]
  }
}

resource nicGatewayInternal 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: '${gatewayName}-eth1'
  location: location
  properties: {
    enableIPForwarding: true
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: { id: vnet.properties.subnets[1].id }
          privateIPAllocationMethod: 'Static'
          privateIPAddress: gatewayInternalIp
        }
      }
    ]
  }
}

resource nicWindows 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: '${windowsName}-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: { id: vnet.properties.subnets[2].id }
          privateIPAllocationMethod: 'Static'
          privateIPAddress: windowsIp
        }
      }
    ]
  }
}

// ------------------------------------------------------------------------------------------ virtual machines

resource gateway 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: gatewayName
  location: location
  identity: { type: 'SystemAssigned' } // required by the Azure Monitor Agent
  properties: {
    hardwareProfile: { vmSize: gatewayVmSize }
    osProfile: {
      computerName: gatewayName
      adminUsername: adminUsername
      customData: base64(cloudInit)
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: { publicKeys: [{ path: '/home/${adminUsername}/.ssh/authorized_keys', keyData: sshPublicKey }] }
      }
    }
    storageProfile: {
      imageReference: { publisher: 'Canonical', offer: 'ubuntu-24_04-lts', sku: 'server', version: 'latest' }
      osDisk: { createOption: 'FromImage', diskSizeGB: 30, managedDisk: { storageAccountType: 'StandardSSD_LRS' } }
    }
    networkProfile: {
      networkInterfaces: [
        { id: nicGatewayExternal.id, properties: { primary: true } }
        { id: nicGatewayInternal.id, properties: { primary: false } }
      ]
    }
    diagnosticsProfile: { bootDiagnostics: { enabled: true } }
  }
}

resource windows 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: windowsName
  location: location
  properties: {
    hardwareProfile: { vmSize: windowsVmSize }
    osProfile: {
      computerName: windowsName
      adminUsername: adminUsername
      adminPassword: windowsAdminPassword
      windowsConfiguration: { enableAutomaticUpdates: true, provisionVMAgent: true }
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsServer'
        offer: 'WindowsServer'
        sku: '2022-datacenter-azure-edition'
        version: 'latest'
      }
      osDisk: { createOption: 'FromImage', managedDisk: { storageAccountType: 'StandardSSD_LRS' } }
    }
    securityProfile: {
      securityType: 'TrustedLaunch'
      uefiSettings: { secureBootEnabled: true, vTpmEnabled: true }
    }
    networkProfile: { networkInterfaces: [{ id: nicWindows.id }] }
    diagnosticsProfile: { bootDiagnostics: { enabled: true } }
  }
}

resource shutdownGateway 'Microsoft.DevTestLab/schedules@2018-09-15' = {
  name: 'shutdown-computevm-${gatewayName}'
  location: location
  properties: {
    status: 'Enabled'
    taskType: 'ComputeVmShutdownTask'
    dailyRecurrence: { time: shutdownTime }
    timeZoneId: 'Romance Standard Time'
    targetResourceId: gateway.id
    notificationSettings: { status: 'Disabled' }
  }
}

resource shutdownWindows 'Microsoft.DevTestLab/schedules@2018-09-15' = {
  name: 'shutdown-computevm-${windowsName}'
  location: location
  properties: {
    status: 'Enabled'
    taskType: 'ComputeVmShutdownTask'
    dailyRecurrence: { time: shutdownTime }
    timeZoneId: 'Romance Standard Time'
    targetResourceId: windows.id
    notificationSettings: { status: 'Disabled' }
  }
}

// ------------------------------------------------------------------------------------------ Log Analytics + Sentinel

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${prefix}-law'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

resource sentinel 'Microsoft.SecurityInsights/onboardingStates@2024-03-01' = {
  scope: workspace
  name: 'default'
  properties: {}
}

var zeekCommon = [
  { name: 'TimeGenerated', type: 'datetime' }
  { name: 'ts_original', type: 'datetime' }
  { name: 'capture', type: 'string' }
  { name: 'uid', type: 'string' }
  { name: 'id_orig_h', type: 'string' }
  { name: 'id_orig_p', type: 'int' }
  { name: 'id_resp_h', type: 'string' }
  { name: 'id_resp_p', type: 'int' }
  { name: 'proto', type: 'string' }
]
var zeekDnsColumns = concat(zeekCommon, [
  { name: 'query', type: 'string' }
  { name: 'qtype_name', type: 'string' }
  { name: 'rcode_name', type: 'string' }
  { name: 'answers', type: 'dynamic' }
])
var zeekConnColumns = concat(zeekCommon, [
  { name: 'service', type: 'string' }
  { name: 'duration', type: 'real' }
  { name: 'orig_bytes', type: 'long' }
  { name: 'resp_bytes', type: 'long' }
  { name: 'orig_ip_bytes', type: 'long' }
  { name: 'resp_ip_bytes', type: 'long' }
  { name: 'conn_state', type: 'string' }
])

resource tableZeekDns 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: 'ZeekDns_CL'
  properties: {
    plan: 'Analytics'
    retentionInDays: 30
    schema: { name: 'ZeekDns_CL', columns: zeekDnsColumns }
  }
}

resource tableZeekConn 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: 'ZeekConn_CL'
  properties: {
    plan: 'Analytics'
    retentionInDays: 30
    schema: { name: 'ZeekConn_CL', columns: zeekConnColumns }
  }
}

resource dce 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = {
  name: '${prefix}-dce'
  location: location
  properties: { networkAcls: { publicNetworkAccess: 'Enabled' } }
}

resource dcrZeek 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: '${prefix}-dcr-zeek'
  location: location
  properties: {
    dataCollectionEndpointId: dce.id
    streamDeclarations: {
      'Custom-ZeekDns': { columns: zeekDnsColumns }
      'Custom-ZeekConn': { columns: zeekConnColumns }
    }
    destinations: { logAnalytics: [{ name: 'law', workspaceResourceId: workspace.id }] }
    dataFlows: [
      { streams: ['Custom-ZeekDns'], destinations: ['law'], transformKql: 'source', outputStream: 'Custom-ZeekDns_CL' }
      { streams: ['Custom-ZeekConn'], destinations: ['law'], transformKql: 'source', outputStream: 'Custom-ZeekConn_CL' }
    ]
  }
  dependsOn: [tableZeekDns, tableZeekConn]
}

resource dcrSyslog 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: '${prefix}-dcr-syslog'
  location: location
  kind: 'Linux'
  properties: {
    dataSources: {
      syslog: [
        {
          name: 'gateway-syslog'
          streams: ['Microsoft-Syslog']
          // kern: nftables log lines; local5: Suricata EVE JSON (rsyslog imfile); auth/daemon for context
          facilityNames: ['kern', 'local5', 'auth', 'daemon']
          logLevels: ['Info', 'Notice', 'Warning', 'Error', 'Critical', 'Alert', 'Emergency']
        }
      ]
    }
    destinations: { logAnalytics: [{ name: 'law', workspaceResourceId: workspace.id }] }
    dataFlows: [{ streams: ['Microsoft-Syslog'], destinations: ['law'] }]
  }
}

resource amaGateway 'Microsoft.Compute/virtualMachines/extensions@2024-07-01' = {
  parent: gateway
  name: 'AzureMonitorLinuxAgent'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.Monitor'
    type: 'AzureMonitorLinuxAgent'
    typeHandlerVersion: '1.0'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: true
  }
}

resource dcrSyslogAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2023-03-11' = {
  scope: gateway
  name: 'gateway-syslog-to-sentinel'
  properties: { dataCollectionRuleId: dcrSyslog.id }
  dependsOn: [amaGateway]
}

// Monitoring Metrics Publisher on the Zeek DCR: lets the deployer upload logs through the Logs Ingestion API
resource ingestRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: dcrZeek
  name: guid(dcrZeek.id, deployerObjectId, '3913510d-42f4-4e42-8a64-420c390055eb')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3913510d-42f4-4e42-8a64-420c390055eb')
    principalId: deployerObjectId
    principalType: 'User'
  }
}

// ------------------------------------------------------------------------------------------ Sentinel content

resource watchlistAssets 'Microsoft.SecurityInsights/watchlists@2024-03-01' = {
  scope: workspace
  name: 'LabAssets'
  properties: {
    displayName: 'LabAssets'
    description: 'Asset inventory of the case 03 lab: private IP address to host name'
    provider: 'Custom'
    source: 'lab-assets.csv'
    itemsSearchKey: 'IpAddress'
    contentType: 'text/csv'
    numberOfLinesToSkip: 0
    rawContent: 'IpAddress,HostName,Role\r\n${windowsIp},${windowsName},Windows endpoint\r\n${gatewayInternalIp},${gatewayName},Gateway (firewall and IPS)\r\n'
  }
  dependsOn: [sentinel]
}

resource connectorDefenderForCloud 'Microsoft.SecurityInsights/dataConnectors@2024-03-01' = {
  scope: workspace
  name: guid(workspace.id, 'AzureSecurityCenter')
  kind: 'AzureSecurityCenter'
  properties: {
    subscriptionId: subscription().subscriptionId
    dataTypes: { alerts: { state: 'Enabled' } }
  }
  dependsOn: [sentinel]
}

var ruleDefaults = {
  enabled: true
  triggerOperator: 'GreaterThan'
  triggerThreshold: 0
  suppressionEnabled: false
  suppressionDuration: 'PT1H'
  eventGroupingSettings: { aggregationKind: 'AlertPerResult' }
}

resource ruleSuricata 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  scope: workspace
  name: guid(workspace.id, 'nthc-rule-01')
  kind: 'Scheduled'
  properties: union(ruleDefaults, {
    displayName: 'NTHC 01 - Suricata IPS alert on the lab gateway'
    description: 'Suricata (inline on the gateway) raised a severity 1-2 alert for traffic from the lab network.'
    severity: 'Medium'
    query: loadTextContent('../../detections/kql/sentinel-rules/01-suricata-ips-alert.kql')
    queryFrequency: 'PT5M'
    queryPeriod: 'PT1H'
    tactics: ['CommandAndControl']
    alertDetailsOverride: { alertDisplayNameFormat: 'Suricata: {{Signature}} ({{SrcIp}} -> {{DstIp}})' }
    entityMappings: [
      { entityType: 'IP', fieldMappings: [{ identifier: 'Address', columnName: 'SrcIp' }] }
      { entityType: 'IP', fieldMappings: [{ identifier: 'Address', columnName: 'DstIp' }] }
    ]
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
      }
    }
  })
  dependsOn: [sentinel]
}

resource ruleDnsTunnel 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  scope: workspace
  name: guid(workspace.id, 'nthc-rule-02')
  kind: 'Scheduled'
  properties: union(ruleDefaults, {
    displayName: 'NTHC 02 - DNS tunnel pattern (Zeek DNS)'
    description: 'One client resolved >= 50 unique, long, high-entropy subdomains of one domain within an hour (case 01).'
    severity: 'High'
    query: loadTextContent('../../detections/kql/sentinel-rules/02-dns-tunnel-zeek.kql')
    queryFrequency: 'PT5M' // lab cadence; hourly is enough in production
    queryPeriod: 'P1D'
    tactics: ['CommandAndControl', 'Exfiltration']
    techniques: ['T1071', 'T1572']
    alertDetailsOverride: { alertDisplayNameFormat: 'DNS tunnel pattern: {{SrcIp}} -> {{BaseDomain}}' }
    entityMappings: [
      { entityType: 'IP', fieldMappings: [{ identifier: 'Address', columnName: 'SrcIp' }] }
      { entityType: 'DNS', fieldMappings: [{ identifier: 'DomainName', columnName: 'BaseDomain' }] }
    ]
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'P1D'
        matchingMethod: 'AllEntities'
      }
    }
  })
  dependsOn: [sentinel, tableZeekDns]
}

resource ruleBeaconing 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  scope: workspace
  name: guid(workspace.id, 'nthc-rule-03')
  kind: 'Scheduled'
  properties: union(ruleDefaults, {
    displayName: 'NTHC 03 - C2 beaconing (Zeek conn)'
    description: 'A client-server pair connects with beacon-like regularity of timing and size for most of a day (case 02).'
    severity: 'High'
    query: loadTextContent('../../detections/kql/sentinel-rules/03-c2-beaconing-zeek.kql')
    queryFrequency: 'PT5M' // lab cadence; hourly is enough in production
    queryPeriod: 'P1D'
    tactics: ['CommandAndControl']
    techniques: ['T1071']
    alertDetailsOverride: { alertDisplayNameFormat: 'Beacon-like traffic: {{Src}} -> {{Dst}}:{{Port}} (score {{Score}})' }
    entityMappings: [
      { entityType: 'IP', fieldMappings: [{ identifier: 'Address', columnName: 'Src' }] }
      { entityType: 'IP', fieldMappings: [{ identifier: 'Address', columnName: 'Dst' }] }
    ]
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'P1D'
        matchingMethod: 'AllEntities'
      }
    }
  })
  dependsOn: [sentinel, tableZeekConn]
}

resource ruleCorrelation 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  scope: workspace
  name: guid(workspace.id, 'nthc-rule-04')
  kind: 'Scheduled'
  properties: union(ruleDefaults, {
    displayName: 'NTHC 04 - Network IDS and endpoint alerts on the same host'
    description: 'The gateway IPS and Defender for Endpoint both alerted on the same host within one hour.'
    severity: 'High'
    query: loadTextContent('../../detections/kql/sentinel-rules/04-network-and-endpoint-correlation.kql')
    queryFrequency: 'PT5M'
    queryPeriod: 'PT2H'
    tactics: ['Execution', 'CommandAndControl']
    alertDetailsOverride: { alertDisplayNameFormat: 'Network and endpoint alerts on {{HostName}}' }
    entityMappings: [
      { entityType: 'Host', fieldMappings: [{ identifier: 'HostName', columnName: 'HostName' }] }
      { entityType: 'IP', fieldMappings: [{ identifier: 'Address', columnName: 'HostIp' }] }
    ]
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
      }
    }
  })
  dependsOn: [sentinel, watchlistAssets]
}

// ------------------------------------------------------------------------------------------ outputs

output workspaceName string = workspace.name
output workspaceCustomerId string = workspace.properties.customerId
output dceIngestionEndpoint string = dce.properties.logsIngestion.endpoint
output dcrZeekImmutableId string = dcrZeek.properties.immutableId
output gatewayName string = gateway.name
output gatewayPublicIp string = gatewayPip.properties.ipAddress
output windowsName string = windows.name
output windowsIp string = windowsIp
