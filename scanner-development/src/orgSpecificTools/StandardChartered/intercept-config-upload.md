# Intercept config upload

## Prerequisites
1. Fetch an API token from [OX dashboard](https://dev.app.ox.security/settings?tab=apiKey)

## Host URL
```
https://dev-api.test-k8s.ox.security/api/file-download-service
```

## GraphQL Endpoint Definition
```graphql
query UploadFile($data: String!, $dataType: UploadDataType!, $connectorName: PolicyFileConnectorName!) {
  uploadFile(data: $data, dataType: $dataType, connectorName: $connectorName) {
    requestId
    success
  }
}
```
- $data - The content of the config JSON
- $dataType - The encoding for the data (ie: Base64)
- $connectorName - The config target (ie: Generic, Kong, Solace)

## Authetication
Bearer Stategy: use the OX API token as JWT for the Authorization header
```
Authorization: "Bearer <OX API token>"
```