# Identify issues in your code with CodeThreat

<img src="https://codethreat.com/images/Codethreat-Logo-kucuk-logo-p-500.png">

Scanning using this github action is very simple. [CodeThreat](https://codethreat.com) is a static application security testing(SAST) solution. It uses scientifically proven techniques with approximation to analyze a codebase at rest, collects security related information, calculates data flows, searches for various well-known security weaknesses and as a result produce claims. These claims are usually whether the targeted codebase is vulnerable to scoped weaknesses or not.

With CodeThreat custom rule engine, we have wide language and framework support without sacrificing quality.

## Requirements

* You must have a codethreat account to use it. [To Sign Up](https://codethreat.com)!
* Thats all. Now you are ready to jump!

## Usage

Copy that yaml file and add it to `.github/workflows/ct.yml` directory.
If it's not fit you directlty you can change action triggers and `FAILED_ARGS`.

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
        uses: CodeThreat/codethreat_scan_action
        env:
           ACCESS_TOKEN: ${{ secrets.ACCESS_TOKEN }}
           GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
           CT_SERVER: ${{ secrets.CT_SERVER }}
           USERNAME: ${{ secrets.USERNAME }}
           PASSWORD: ${{ secrets.PASSWORD }}
        with: 
            FAILED_ARGS: |
                 - max_number_of_critical=4
                 - max_number_of_high=20
                 - weakness_is="*.injection,buffer.over.read,mass.assigment"
                 - condition = 'OR'
                 - automerge = true

```

* If `FAILED_ARGS` conditions applies the scan results for the values you will give, it is the part where you will fail the action. 

* In env section, you can use ACCESS_TOKEN or USERNAME, PASSWORD one of the authentication methods is required.

* Mininum one of `FAILED_ARGS` fields is required. Args are merge with the `and` condition between themselves.

* `weakness_is` fields expects both a wildcard or a direct weakness id.
You can find all the following weakness ids [here](https://codethreat.com).

## Args

| Variable  | Example Value &nbsp;| Description &nbsp; | Type | Required | Default |
| ------------- | ------------- | ------------- |------------- | ------------- | ------------- |
| max_number_of_critical | 5 | Failed condition for maximum critical number of found issues | Number | No | N/A
| max_number_of_high | 20 | Failed condition for maximum high number of found issues | Number | No | N/A
| weakness_is | "*.injection,buffer.over.read,mass.assigment" | Failed condition for found issues weakness id's. | String | No | N/A
| automerge | true | If automerge is active and scan returns success, it allows PR to merge automatically . | Boolean | No | false
| condition | "OR" | It checks failed arguments(max_number_of_critical, max_number_of_high)  using with "and" or "or". | String | No | AND


### Secrets

- `ACCESS_TOKEN` – A given JWT token when you logged in your account in access_token field.

- `USERNAME` –  Your CodeThreat Account's username.

- `PASSWORD` – Your CodeThreat Account's passowrd.

- *`GITHUB_TOKEN` – It's provided by the github when action triggers. You do not need to add it separately from the secrets tab.

## Example of pull request check out comment

<img src="./images/example_of_comment.png">