param location string = resourceGroup().location
resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-arb-conformance-bot'
  location: location
}
