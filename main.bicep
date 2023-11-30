param registryName string
param registryloc string = 'Central US'



module registry './modules/container-registry/registry/main.bicep' = {
  name: registryName
  params: {
    name: registryName
    location: registryloc
    acrAdminUserEnabled: true
    
  }
}

