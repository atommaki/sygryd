# Sygryd

SBOM and vulnerability scan service for docker images. It provides a REST API to submit images, retrieve SBOMs and vulnerability scan results. It is python based and the only interface is REST API and a Swagger UI for it (so no real GUI).

Sygryd:
 * uses [syft](https://github.com/anchore/syft) for SBOM scanning,
 * uses [grype](https://github.com/anchore/grype) for vulnerability scanning,
 * uses PosgreSQL to store all results


# Installation (the supported way)
The mainly supported way to run Sygryd is docker-compose based.
Clone this repository and in the repo, and build the images:

```
docker compose build --no-cache sygryd-base
docker compose build --no-cache
```

Edit the `.env` file to set up `POSTGRES_PASSWORD`, after that simply run:

```
docker compose up -d
```

Open http://localhost:5000 for the Swagger UI.


Something is wrong? Check the logs:
```
docker logs --follow sygryd-backend
```
```
docker logs --follow sygryd-rest
```

# Installation (on your own)
Sygryd contains 2 python applications (the REST service and a backend), you can run those manually. Before you start, you need a postgreSQL database and provide the credentials for the DB in the `.env` file.

Note: run all of the following command in the root of this repository.

The easiest way to start one in Docker:
```
docker run -d \
  --name sygryd-postgres \
  --env-file .env \
  -p 5432:5432 \
  -v "$(pwd)/postgres-init.sql:/docker-entrypoint-initdb.d/init.sql" \
  postgres:latest

```

Then for the python components be sure you have all the needed packages:
```
pip install -r requirements.txt
```

start the backend service:
```
python src/sygryd-backend.py

```

start the rest service:
```
python src/sygryd-rest.py
```

# Basic usage

First of all, instead of these examples you may just want to check the provided Swagger page (http://localhost:5000)

### Check if the service is running:

```
curl --silent -X 'GET' 'http://localhost:5000/servicestatus' -H 'accept: application/json' | jq .
```
example response:
```
{
  "status": "running happily",
  "imagesInDB": {
    "total": 761,
    "complete": 708,
    "failed": 53,
    "waitingForSBOM": 0,
    "waitingForVulnerabilityScan": 0,
    "latestImageSubmit": "2025-04-07T23:48:46.792469",
    "latestSbomScan": "2025-04-07T23:54:25.404147",
    "latestVulnerabilityScan": "2025-04-07T23:54:29.127759",
    "latestDockerPullFailure": "2025-03-29T13:19:18.823574"
  }
}
```

### Submit images:

```
curl -X 'POST' \
  'http://localhost:5000/submit' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{ "images": [ "postgres:16.8", "postgres:17.4", "debian:12.10" ] }'
```
example response:
```
{
  "added": 3,
  "reset": 0,
  "ignored": 0
}
```
### Check status of images

```
curl -X 'GET' \
  'https://sygryd.bergauer.dev/list?filter=postgres%25&image-status=any&details=true' \
  -H 'accept: application/json'
```

<details>
<summary>example response:</summary>

    {
      "images": [
        {
          "image": "postgres:16.8",
          "submitted_timestamp": "2025-04-01T12:54:47.109651",
          "docker_pull_failed": 0,
          "docker_pull_failed_timestamp": null,
          "sbom_timestamp": "2025-04-01T23:54:37.452496",
          "sbom_json_size": 6990686,
          "sbom_duration_sec": 23,
          "vscan_timestamp": "2025-04-01T23:54:39.695446",
          "vscan_json_size": 621423,
          "vscan_duration_sec": 1,
          "vscan_summary": {
            "Low": 18,
            "High": 42,
            "Medium": 44,
            "Unknown": 4,
            "Critical": 7,
            "Negligible": 96
          }
        },
        {
          "image": "postgres:17.4",
          "submitted_timestamp": "2025-04-01T12:54:47.117930",
          "docker_pull_failed": 0,
          "docker_pull_failed_timestamp": null,
          "sbom_timestamp": "2025-04-01T23:54:56.580462",
          "sbom_json_size": 7010712,
          "sbom_duration_sec": 17,
          "vscan_timestamp": "2025-04-01T23:54:59.108911",
          "vscan_json_size": 621423,
          "vscan_duration_sec": 1,
          "vscan_summary": {
            "Low": 18,
            "High": 42,
            "Medium": 44,
            "Unknown": 4,
            "Critical": 7,
            "Negligible": 96
          }
        }
      ],
      "truncated": false
    }

</details>

### Download SBOM/vulnerability scan results

Note: the result can be a very large json file!

SBOM:
```
curl -X 'POST' \
  'http://localhost:5000/get-sbom-json' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{ "image": "postgres:16.8" }' > postgres-16.8-sbom.json
```

Vulnerability scan:
```
curl -X 'POST' \
  'https://sygryd.bergauer.dev/get-vscan-json' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{ "image": "postgres:16.8" }' > postgres-16.8-vulnerabilities.json
```
