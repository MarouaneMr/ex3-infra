param registryName string
param location string = 'Central US'
param serverfarmName string
param webAppName string
param containerRegistryImageName string
param containerRegistryImageVersion string
param DOCKER_REGISTRY_SERVER_USERNAME string
param DOCKER_REGISTRY_SERVER_URL string
@secure()
param DOCKER_REGISTRY_SERVER_PASSWORD string


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
    reserved: true
  }
}

module webApp './modules/web/site/main.bicep' = {
  name: webAppName
  params: {
    name: webAppName
    location: location
    kind: 'app'
    serverFarmResourceId: servicePlan.outputs.resourceId
    siteConfig: {
      linuxFxVersion: 'DOCKER|${containerRegistryName}.azurecr.io/${containerRegistryImageName}:${containerRegistryImageVersion}'
      appCommandLine: ''
    }
    appSettingsKeyValuePairs: {
      WEBSITES_ENABLE_APP_SERVICE_STORAGE: false
      DOCKER_REGISTRY_SERVER_URL: DOCKER_REGISTRY_SERVER_URL
      DOCKER_REGISTRY_SERVER_USERNAME: DOCKER_REGISTRY_SERVER_USERNAME
      DOCKER_REGISTRY_SERVER_PASSWORD: DOCKER_REGISTRY_SERVER_PASSWORD
    }
  }
}
