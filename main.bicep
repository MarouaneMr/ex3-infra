param registryName string
param location string = 'Central US'



module registry './modules/container-registry/registry/main.bicep' = {
  name: registryName
  params: {
    name: registryName
    location: location
    acrAdminUserEnabled: true
    
  }
}

