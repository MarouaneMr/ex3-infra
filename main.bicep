param registryName string
param location string = 'Central US'
param serverfarmName string


module registry './modules/container-registry/registry/main.bicep' = {
  name: registryName
  params: {
    name: registryName
    location: location
    acrAdminUserEnabled: true
    
  }
}

module serverfarm './modules/web/serverfarm/main.bicep' = {
  name: serverfarmName
  params: {
    name: serverfarmName
    location: location
    sku: {
      capacity: 1
      family: 'B'
      name: 'B1'
      size: 'B1'
      tier: 'Basic'
    }
    kind: 'Linux'
    reserved: true
  }
}
