# Prototype application to parse multiple ACS endpoints collect metadata via the API, correlate and parse out JSON files.

# Configuration
- Configuration settings are mostly obtained from enviromnet variables. Configuration settings are provided and explained in [config file](./config.py)

- The list of endpoints for the app to poll can be set via ENDPOINT_LIST_JSON_PATH environment variable. The environment variable should point to a json file with API details. A sample file is provided in [endpoint_list.json](./endpoint_list.json).While environment details are provided via the previously mentioned variable the token used for connection is obtained via enviroment variable. And the token environment variable must be set in the endpoint json file and defined by field "endpoint_token_env_variable_name".

- At the moment the app is set out to generate a single output of file with the list of clusters, their deployments and alerts.

Run Locally 
- Build Image 
    ```bash
    podman build -t quick_acs_app .
    ```

- Run Container
  ```bash
  podman run --env $MAIN_ACS_TOKEN --env OUTPUT_FOLDER=/output -v /tmp/output:/output:Z localhost/quick_acs_app
  ```