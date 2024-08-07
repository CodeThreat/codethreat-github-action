# Identify issues in your code with CodeThreat

<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://codethreat.com">
    <img src="https://www.codethreat.com/_next/static/media/ct-logo.0cc6530f.svg" alt="Logo" width="259" height="39">
  </a>

  <h3 align="center">CodeThreat Github Action</h3>

</p>

[CodeThreat](https://codethreat.com) SAST solution has seamless integration with the [GitHub Actions](https://github.com/features/actions). While it's fairly easy to start security scans and working on the issues found on your code, this document provides details of the integration. 

With CodeThreat custom rule engine, we have wide language and framework support without sacrificing quality.

## Requirements

* A [CodeThreat](https://codethreat.com) account. Contact info@codethreat.com if you don't have one yet.
* Aaand that's all! Now you are ready to jump!
  
## Github Security Feed Example

<img src="./images/github_action.png">

## Usage

Create a YAML file, such as the one below, `.github/workflows/ct.yml` under your source code project root directory. You can tailor the action triggers and `FAILED_ARGS` according to your needs.

```yaml
on:
  # Trigger scan when pushing in master or pull requests, and when creating
  # a pull request.
  pull_request:
      branches:
        - main
  push: 
        branches:
        - main
jobs:
  codethreat_scanner:
    runs-on: ubuntu-latest
    name: Codethreat Github Actions
    steps:
      - name: Check Out Source Code
        uses: actions/checkout@v3
      - name: Install Node.js
        uses: actions/setup-node@v1
      - name: CodeThreat Scanner
        uses: CodeThreat/codethreat-scan-action@master
        env:
           ACCESS_TOKEN: ${{ secrets.ACCESS_TOKEN }}
           GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
           CT_SERVER: ${{ secrets.CT_SERVER }}
           USERNAME: ${{ secrets.USERNAME }}
           PASSWORD: ${{ secrets.PASSWORD }}
           ORGNAME: ${{ secrets.ORGNAME }}
        with: 
            FAILED_ARGS: |
                 - max_number_of_critical: 23
                 - max_number_of_high: 23
                 - sca_max_number_of_critical: 23
                 - sca_max_number_of_high: 23
                 - weakness_is: ".*injection,buffer.over.read,mass.assigment"
                 - condition: 'OR'
                 - automerge: true
                 - sync_scan: true
                 - policy_name: Advanced Security
      - name: Upload SARIF file
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: codethreat.sarif.json
```

* As the name implies `FAILED_ARGS` contains the conditions for which you want to break the pipeline (action).

* In `env` section, you can use either the ACCESS_TOKEN or USERNAME,PASSWORD pair as one of the authentication method.

* Mininum one  `FAILED_ARGS` fields is required. If more args are provided, they will be `AND`ed together.

* `weakness_is` fields expects either a wildcard or a direct weakness id. Please checkout KStore section of  [CodeThreat](https://codethreat.com) portal application.

## Args

| Variable  | Example Value &nbsp;| Description &nbsp; | Type | Required | Default |
| ------------- | ------------- | ------------- |------------- | ------------- | ------------- |
| max_number_of_critical | 23 | Failed condition for maximum critical number of found issues | Number | No | N/A
| max_number_of_high | 23 | Failed condition for maximum high number of found issues | Number | No | N/A
| sca_max_number_of_critical | 23 | Failed condition for maximum high number of found sca issues | Number | No | N/A
| sca_max_number_of_high | 23 | Failed condition for maximum high number of found sca issues | Number | No | N/A
| weakness_is | ".*injection,buffer.over.read,mass.assigment" | Failed condition for found issues weakness id's. | String | No | N/A
| automerge | true | If automerge is active and scan returns success, it allows PR to merge automatically . | Boolean | No | false
| condition | "OR" | It checks failed arguments(max_number_of_critical, max_number_of_high)  using with "and" or "or". | String | No | AND
| sync_scan | true | If you don't want to wait for the pipeline to finish scanning, set it to false | Boolean | No | true
| policy_name | "Advanced Security" | For example, Advanced Security, SAST Scan, SCA Scan, etc. By default Advanced Security | String | No | Advanced Security


### Secrets

- `ACCESS_TOKEN` – Your CodeThreat Account's token. It refers to the API Token that you need to generate in the application for CodeThreat.

- `USERNAME` –  Your CodeThreat Account's username.

- `PASSWORD` – Your CodeThreat Account's password.

- `ORGNAME` – Your CodeThreat Account's orgname.

- *`GITHUB_TOKEN` – It represents the Github token belonging to your account. There is no need to add it manually. Github adds this automatically. However, if you want to import a token with different authorizations, you can enter the secret section of your repo with the same name.

- There may be some permission restrictions for GITHUB_TOKEN. To remove them, first make sure that the "Read and Write Permission" option is selected in the settings section of your repository. If you are using CodeThreat Action in an organization, you can do this in the settings section of your organization. Another method is to add the permission line to the .yaml file, for example: You can solve this situation with ``permissions: write-all``.
