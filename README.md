# k8s-db-collector


[![Go Report Card][report-card-img]][report-card]
[![License][license-img]][license]
[![k8s-db-collector repo](https://github.com/aquasecurity/k8s-db-collector/actions/workflows/update.yml/badge.svg)](https://github.com/aquasecurity/k8s-db-collecotr/actions/workflows/update.yml)

[report-card-img]: https://goreportcard.com/badge/github.com/aquasecurity/k8s-db-collector
[report-card]: https://goreportcard.com/report/github.com/aquasecurity/k8s-db-collector
[license-img]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
[license]: https://github.com/aquasecurity/k8s-db-collector/blob/main/LICENSE

Collect k8s deprecated and removed API information and save it in parsable format automatically here are ref.
 - [kubernetes deprecation-guide](https://raw.githubusercontent.com/kubernetes/website/main/content/en/docs/reference/using-api/deprecation-guide.md)
 - [kubernetes openapi-spec](https://raw.githubusercontent.com/kubernetes/kubernetes/master/api/openapi-spec/swagger.json)
 - [kubernetes api source code](https://github.com/kubernetes/kubernetes/tree/master/staging/src/k8s.io/api)

## Data
https://github.com/aquasecurity/trivy-db-data/

## Usage

```
$ k8s-db-collector -h
Usage of k8s-db-collector:
  -target string
        update target ()
```
