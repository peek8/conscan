<p align="center">
    <img alt="Conscan logo" src="resources/conscan-logo.png" width="200">
</p>


# Conscan
**Secure, lean, and compliant containers made simple.**

Scans a container image for`vulnerabilities`, `exposed secrets`, `inefficient file storage`, `OS packages and software dependencies in use (SBOM)` and `check CIS(Center for Internet Security) Benchmarks`.

**Conscan Report in CLI (Table Format):**
![Image](https://github.com/user-attachments/assets/42cc02b1-c7d4-47b8-a5f8-f837163f8096)

**Conscan Report in HTML Format:**
![Image](https://github.com/user-attachments/assets/d40f573f-9a30-4bb2-9618-591c498033fd)

# 📖 Introduction

Conscan is a lightweight yet powerful container image scanning tool that helps you secure and optimize your container workloads.
It analyzes container images for potential security risks, misconfigurations, and inefficiencies—giving developers and DevOps teams actionable insights before deploying to production.

With conscan, you can:

- Detect vulnerabilities in OS packages and application dependencies.
- Identify exposed secrets inside images.
- Generate SBOM (Software Bill of Materials) for transparency and compliance.
- Spot inefficient file storage that bloats images.
- Validate container security against CIS Benchmarks.
- Export results in JSON, table, or HTML formats for easy integration and reporting.
- Scan both local images and images from remote registries (e.g., Docker Hub).
- By integrating conscan into your CI/CD pipeline, you can shift security left and ensure your containers are secure, lean, and compliant from the very beginning.

# 💡 Motivation

There are already great security tools like Trivy, Grype, and Syft — so why build conscan?

While working with containerized applications, I noticed a few gaps when using these tools individually:

- 🔀 Fragmented Workflows → Each tool specializes in one area (vulnerabilities, SBOM, secrets, CIS), which often requires juggling multiple commands and parsing different outputs.

- 📑 Inconsistent Reporting → Output formats and structures vary between tools, making it harder to integrate results into CI/CD pipelines or share with teams.

- 🖥 Developer Experience → New users often struggle with setup, remembering CLI flags, and combining results from multiple scanners.

- 📦 One-stop Scanning → Sometimes you just want to run a single command against an image and get everything — vulnerabilities, SBOM, secrets, CIS checks, and efficiency hints.

Conscan was built to address these pain points by:

- Providing a unified interface to multiple best-in-class scanners.
- Normalizing results into consistent outputs (table, JSON, HTML).
- Supporting both local and remote images seamlessly.
- Focusing on developer-first usability and CI/CD integration.

In short:
👉 Conscan doesn’t try to reinvent the wheel — it puts the best wheels together on one car. 🚗💨

# ✨ Features
### 🔍 Vulnerability Scanning
Scans OS packages and software dependencies against known vulnerabilities.

### 🔑 Secret Detection
Detects API keys, tokens, and other sensitive information accidentally embedded in images.

### 📦 SBOM Generation
Produces a detailed Software Bill of Materials for visibility into components in use.

### 📂 Storage Efficiency Analysis
Highlights large or unnecessary files that increase image size.

### 🛡 CIS Benchmark Checks
Validates images against Center for Internet Security (CIS) recommendations.

### 📝 Flexible Report Formats
Supports JSON, table, and HTML outputs for automation, human readability, and sharing.

### 🖥 Local & Remote Image Support
Works with images stored locally or pulled directly from remote registries like Docker Hub.

### ⚡ Fast & CI/CD Friendly
Designed to be easily integrated into build pipelines with minimal overhead.

# 🛠 Powered By

Conscan leverages well-established open-source security and compliance tools under the hood, combining their strengths into a single unified workflow:

- [Trivy](https://github.com/aquasecurity/trivy) → Vulnerability scanning, secret detection, and misconfigurations
- [Grype](https://github.com/anchore/grype) → Deep vulnerability scanning of OS packages and application dependencies
- [Syft](https://github.com/anchore/syft) → SBOM (Software Bill of Materials) generation
- [Dive](https://github.com/wagoodman/dive) → Check inefficient files by discovering ways to shrink the size of your Docker/OCI image.
- [Dockle](https://github.com/goodwithtech/dockle) → Container Image Linter for Security, Check CIS Benchmarks 

By orchestrating these tools behind the scenes, conscan provides a streamlined developer experience with consistent reporting, multiple output formats, and optional CIS benchmark validation.

# 🔧 Installation
## Pre-Requisites
If you want to install the binary at your machine, you need to install the following tools to make the binary work:
- [Trivy](https://github.com/aquasecurity/trivy) 
- [Grype](https://github.com/anchore/grype) 
- [Syft](https://github.com/anchore/syft) 
- [Dive](https://github.com/wagoodman/dive)
- [Dockle](https://github.com/goodwithtech/dockle)

You can go to the corresponding sites and install them as per the installation guide, or can use [install-dependencies.sh](./scripts/install-dependencies.sh) script.

## Binary
You can get the latest version binary from [releases page](https://github.com/peek8/conscan/releases).

Download the archive file for your operating system/architecture. Unpack the archive, and put the binary somewhere in your `$PATH` (on UNIX-y systems, `/usr/local/bin` or the like).
you can check your os at terminal using command: `$uname -s` and architecture by `$uname -m`.
For example, if your os is `Darwin` and architecture is `arm64`, you can run the following command to install:

```bash
$ conscan_version=0.1.0-alpha1
$ wget -qO- "https://github.com/peek8/conscan/releases/download/v${conscan_version}/conscan_${conscan_version}_darwin_arm64.tar.gz" | tar -xz -C /usr/local/bin conscan
```

- NOTE: Make sure that the binary is executable. (`chmod +x conscan`)

## Use Docker
You can also run the `conscan` using the Container Image: 

```bash
$ docker run --rm -it \
--name conscan ghcr.io/peek8/conscan:latest \
scan $(ImageName):$(ImageTag)
```
For example, to scan the `alpine:latest` image, you can use:
```bash
$ docker run --rm -it \
--name conscan  ghcr.io/peek8/conscan:latest \
scan alpine:latest
```

<details>
<summary>Result</summary>

https://github.com/user-attachments/assets/25f07a13-69fc-47ec-adaa-3c4f7a40df19

</details>

> It is highly recommended to mount a persistent cache dir on the host into the Conscan container. This will make the scanning as it will persist the Vulnerability(and other) Databases.

Example:
```bash
$ docker run --rm -it \
    -v ./cache:/.cache \     
    --name conscan  ghcr.io/peek8/conscan:latest \
    scan alpine:lates
```

You can see all the available image tags at [github container repository](https://github.com/peek8/conscan/pkgs/container/conscan).

# 🚀 Quick Start

## General Usage

```bash
$ conscan scan [Flags] yourimage:tag
```

Examples:

**Scan a container image locally available which uses the Podman/Docker daemon for local images**
```bash
$ conscan scan alpine-sec:1.0
```
<details>
<summary>Result</summary>

https://github.com/user-attachments/assets/5b99fe08-f37a-4a3c-ab73-b9162fddfc9f


</details>

**Scan container images from registry eg. dockerhub**
```bash
$ conscan scan docker.io/yourimage:tag
```

or from github image repo
```bash
$ conscan scan ghcr.io/yourimage:tag
```

**By default, `conscan` will scan everything. If you are interested for specific scan report, you can use the flag `--scanners` with comma separated values. The supported values are: `[vuln secret package cis storage]`. For example, to scan for only vulnerabilities and exposed secrets you can use like:**
```bash
$ conscan scan --scanners=vuln,secret yourimage:tag
```

## 📊 Report Formats

Conscan supports multiple output formats to fit different workflows:

- Table → Human-readable in CLI
- JSON → For integration with pipelines & automation
- HTML → Shareable reports for teams and auditors

To get report in different format, you can use the flag `--format`(-f in short). Supported values are: `[json table html]`, if not provided default format is `table`.

### Examples:

**By default, table format report**
```bash
$ conscan scan alpine-sec:1.0
```
<details>
<summary>Result</summary>

https://github.com/user-attachments/assets/5b99fe08-f37a-4a3c-ab73-b9162fddfc9f

</details>

**HTML format report: to view the html its better to save report to a file and view the report in a browser, In that case you can use --output flag**
```bash
$ conscan scan --format html --output report.html alpine-sec:1.0
```
<details>
<summary>Result</summary>

https://github.com/user-attachments/assets/47cf69c4-a11f-4244-80f1-8f25af42e8e0

</details>

**JSON format report**

```bash
$ conscan scan --format html --output report.html alpine-sec:1.0
```

<details>
<summary>Sample Json output</summary>

```json
{
  "CreatedAt": "2025-10-01T11:37:31.562284+06:00",
  "CreatedAtStr": "2025-10-01 05:37:31 UTC",
  "ArtifactName": "alpine-sec:1.0",
  "ArtifactType": "container_image",
  "metadata": {
    "Size": 8463360,
    "sizeStr": "8 MB",
    "OS": {
      "Family": "alpine",
      "Name": "3.22.0_alpha20250108"
    },
    "ImageID": "sha256:cf7a952180715b0ae2148cc8d832130bd008a295e707d7f8fdc3bdf144b630ba",
    "RepoTags": [
      "docker.io/asraf344/alpine-sec:1.0",
      "ghcr.io/asraf344/alpine-sec:1.0",
      "localhost/alpine-sec:1.0"
    ],
    "RepoDigests": [
      "docker.io/asraf344/alpine-sec@sha256:924f7457fa28ebd1e55c8d142e8f866a8020eaea4f2f9ec92bc47ef1ae7135ba",
      "ghcr.io/asraf344/alpine-sec@sha256:924f7457fa28ebd1e55c8d142e8f866a8020eaea4f2f9ec92bc47ef1ae7135ba",
      "localhost/alpine-sec@sha256:924f7457fa28ebd1e55c8d142e8f866a8020eaea4f2f9ec92bc47ef1ae7135ba"
    ],
    "ImageConfig": {
      "architecture": "arm64",
      "os": "linux",
      "created": "2025-09-23T11:01:55.383691556Z"
    }
  },
  "vulnerabilities": [
    {
      "VulnerabilityID": "CVE-2025-26519",
      "PkgID": "musl@1.2.5-r9",
      "PkgName": "musl",
      "InstalledVersion": "1.2.5-r9",
      "FixedVersion": "1.2.5-r10",
      "Status": "fixed",
      "DataSourceURL": "https://security.alpinelinux.org/vuln/CVE-2025-26519",
      "Title": "musl libc 0.9.13 through 1.2.5 before 1.2.6 has an out-of-bounds write ...",
      "Description": "musl libc 0.9.13 through 1.2.5 before 1.2.6 has an out-of-bounds write vulnerability when an attacker can trigger iconv conversion of untrusted EUC-KR text to UTF-8.",
      "Severity": "High",
      "_": 4,
      "CweIDs": [
        "CWE-787"
      ],
      "CvssScore": 8.1,
      "References": [
        "http://www.openwall.com/lists/oss-security/2025/02/13/2",
        "http://www.openwall.com/lists/oss-security/2025/02/13/3",
      ],
      "PublishedDate": "2025-02-14T04:15:09.05Z",
      "LastModifiedDate": "2025-02-14T17:15:23.09Z"
    }
  ],
  "vulnerabilitySummary": {
    "totalCount": 14,
    "criticalCount": 0,
    "highCount": 2,
    "mediumCount": 6,
    "lowCount": 6,
    "unknowsCount": 0
  },
  "secrets": [
    {
      "Target": "/tst.txt",
      "Category": "GitHub",
      "Severity": "CRITICAL",
      "Title": "GitHub Personal Access Token",
      "StartLine": 4,
      "EndLine": 7,
      "Content": "\n# Fake GitHub Token\nGITHUB_TOKEN=****************************************1234",
      "Description": "Secret(s) found in file system",
      "LocationType": "FileSystem"
    },
    {
      "Target": "/tst.txt",
      "Category": "Slack",
      "Severity": "MEDIUM",
      "Title": "Slack Webhook",
      "StartLine": 7,
      "EndLine": 10,
      "Content": "\n# Fake Slack Webhook\nSLACK_WEBHOOK=*****************************************************************************",
      "Description": "Secret(s) found in file system",
      "LocationType": "FileSystem"
    },
    {
      "Target": "alpine-sec:1.0",
      "Category": "GitHub",
      "Severity": "CRITICAL",
      "Title": "GitHub Personal Access Token",
      "StartLine": 45,
      "EndLine": 48,
      "Content": "\n  \"Env\": [\n  \"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\",\n  \"GITHUB_TOKEN=****************************************6759\"\n  ],",
      "Description": "Secret(s) found in Environment Variables",
      "LocationType": "EnvVar"
    }
  ],
  "sboms": {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "alpine-sec",
    "documentNamespace": "https://anchore.com/syft/image/alpine-sec-3bf7b6ab-6c74-4153-8346-e2079f0be8ef",
    "creationInfo": {
      "licenseListVersion": "3.27",
      "creators": [
        "Organization: Anchore, Inc",
        "Tool: syft-1.32.0"
      ],
      "created": "2025-10-01T05:37:33Z"
    },
    "packages": [
      {
        "name": "alpine-baselayout",
        "SPDXID": "SPDXRef-Package-apk-alpine-baselayout-3eb66fe65cb1f527",
        "versionInfo": "3.6.8-r1",
        "supplier": "Person: Natanael Copa (ncopa@alpinelinux.org)",
        "originator": "Person: Natanael Copa (ncopa@alpinelinux.org)",
        "downloadLocation": "https://git.alpinelinux.org/cgit/aports/tree/main/alpine-baselayout",
        "filesAnalyzed": true,
        "packageVerificationCode": {
          "packageVerificationCodeValue": "6a22bff30e2aed347029eeb9d51c810613705455"
        },
        "sourceInfo": "acquired package info from APK DB: /lib/apk/db/installed",
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "GPL-2.0-only",
        "copyrightText": "NOASSERTION",
        "description": "Alpine base dir structure and init scripts",
        "externalRefs": [
          {
            "referenceCategory": "SECURITY",
            "referenceType": "cpe23Type",
            "referenceLocator": "cpe:2.3:a:alpine-baselayout:alpine-baselayout:3.6.8-r1:*:*:*:*:*:*:*"
          },
          {
            "referenceCategory": "SECURITY",
            "referenceType": "cpe23Type",
            "referenceLocator": "cpe:2.3:a:alpine-baselayout:alpine_baselayout:3.6.8-r1:*:*:*:*:*:*:*"
          }
        ]
      }
    ]
  },
  "cisScans": {
    "image": "alpine-sec:1.0",
    "summary": {
      "fatal": 1,
      "warn": 1,
      "info": 2,
      "skip": 0,
      "pass": 12
    },
    "details": [
      {
        "code": "CIS-DI-0010",
        "title": "Do not store credential in environment variables/files",
        "level": "FATAL",
        "alerts": [
          "Suspicious ENV key found : GITHUB_TOKEN on /bin/sh -c #(nop) ENV GITHUB_TOKEN=******* (You can suppress it with --accept-key)"
        ]
      },
      {
        "code": "CIS-DI-0001",
        "title": "Create a user for the container",
        "level": "WARN",
        "alerts": [
          "Last user should not be root"
        ]
      },
      {
        "code": "CIS-DI-0005",
        "title": "Enable Content trust for Docker",
        "level": "INFO",
        "alerts": [
          "export DOCKER_CONTENT_TRUST=1 before docker pull/build"
        ]
      },
      {
        "code": "CIS-DI-0006",
        "title": "Add HEALTHCHECK instruction to the container image",
        "level": "INFO",
        "alerts": [
          "not found HEALTHCHECK statement"
        ]
      }
    ]
  },
  "storageAnalysis": {
    "image_source": "",
    "efficiency": 100,
    "wasted_bytes": 0,
    "wasted_bytes_human": "0 B",
    "user_wasted_percent": 0,
    "inefficient_files": [],
    "results": [
      {
        "name": "highestUserWastedPercent",
        "status": "PASS"
      },
      {
        "name": "lowestEfficiency",
        "status": "PASS"
      }
    ]
  }
}
```

</details>

You can download/view the full JSON here: [resources/sample-json-report.json](./resources/sample-json-report.json)


# Private Registry Authentication

## Local Registry Credentials
If you are in your laptop/PC and want to use the conscan at CLI, then to scan an image from private registry, you have to [docker login](https://docs.docker.com/reference/cli/docker/login/) first.

When a container runtime is not present, conscan can still utilize credentials configured in common credential sources (such as `~/.docker/config.json`). It will pull images from private registries using these credentials.

The common syntax of docker login command is:
```bash
$ docker login registry.example.com --user your-user --password superSecret
```

- If you have token, you can use that as password, eg to login dockerhub using token, you can use following command:

```bash
$ echo $DOCKER_TOKEN | podman login docker.io -u your-user --password-stdin
```
- Same way for Github Registry:

```bash
$ echo $CR_PAT | docker login ghcr.io -u your-user --password-stdin
```

- For AWS ECR, you have to get login password first and use that at `docker login`, eg

```bash
$ aws ecr get-login-password --region $AWS_REGION \
  | docker login --username AWS \
    --password-stdin 123456.dkr.ecr.$AWS_REGION.amazonaws.com
```
Note: The above aws command will work provided that you have the proper aws configuration settings for aws cli. One easy option is to use environment variables like:

```bash
$ export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
$ export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
$ export AWS_REGION=us-west-2
```
There are other options, see more details at [Configuring settings for the AWS CLI](https://docs.aws.amazon.com/cli/v1/userguide/cli-chap-configure.html) page.

> For all the private registry while using `conscan` to scan image use the Full Image path with registry, eg:
```bash
$ conscan scan registry.example.com/your-image:tag
``` 

## Registry Credentials in Container
If you want to use docker/podman to scan some images from private registry, the easy way would be to mount the `docker config.json` into container. 

For example, in some linux machine:

```bash
$ docker run --rm -it \
  -v ./cache:/.cache \
  -v ~/.docker/config.json:/.docker/config.json  \ 
  --name conscan  ghcr.io/peek8/conscan:latest \
  scan registry.example.com/your-image:tag
```

At Mac, the docker config.json file might be at path `~/.config/containers/auth.json`, in that case it would be:

```bash
$ docker run --rm -it \
  -v ./cache:/.cache \
  -v ~/.config/containers/auth.json:/.docker/config.json  \ 
  --name conscan  ghcr.io/peek8/conscan:latest \
  scan registry.example.com/your-image:tag
```

## Registry Credentials in Kubernetes
### Use Simple Secret
You can create a Secret using the above mentioned `~/.docker/config.json`. And mount that secret in the conscan container.
- Create secret `secret.yaml` using config.json
```yaml
    apiVersion: v1
    kind: Secret
    metadata:
      name: registry-config
      namespace: awesomeapp
    data:
      config.json: <base64 encoded config.json>
```

Apply it:
```bash
$ kubectl apply -f secret.yaml
```

- Create your pod running conscan. The  `config.json` file needs to be mounted at `/.docker/config.json`. here's pod.yaml:

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    - image: ghcr.io/peek8/conscan:latest 
      name: conscan-private-registry
      volumeMounts:
      - mountPath: /.docker
        name: registry-config
        readOnly: true
      args:
        -  scan 
        - "registry.example.com/your-image:tag"
  volumes:
  - name: registry-config
    secret:
      secretName: registry-config
```
- Apply pod.yaml

```bash
$ kubectl apply -f pod.yaml
```

> Note: At `args` section of pod, you can add `--format` to get different formats than table eg. `--format json` for json format. And to save it to a file use --output.

### Use Image Pull Secret
You can also create secret of type `kubernetes.io/dockerconfigjson` that can be used in Pod at `imagePullSecrets` field.

The secret would be in format:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: regcred
  namespace: awesomeapps
data:
  .dockerconfigjson: UmVhbGx5IHJlYWxseSByZWVlZWVlZWVlZWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGx5eXl5eXl5eXl5eXl5eXl5eXl5eSBsbGxsbGxsbGxsbGxsbG9vb29vb29vb29vb29vb29vb29vb29vb29vb25ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubmdnZ2dnZ2dnZ2dnZ2dnZ2dnZ2cgYXV0aCBrZXlzCg==
type: kubernetes.io/dockerconfigjson
```

And the `pod.yaml` will be like:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: private-reg
spec:
  containers:
  - image: ghcr.io/peek8/conscan:latest 
    name: conscan-private-registry
  imagePullSecrets:
  - name: regcred
```
See more about using imagePullSecrets at [Kubernetes Private Registry doc](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/)

<!-- 
# ⚙️ Integration with CI/CD

Show how to plug it into GitHub Actions, GitLab CI, Jenkins, etc.
(Sample YAML snippet for GitHub Actions or GitLab would help.)

# 📌 Roadmap

(Optional — upcoming features you plan to add, e.g. multi-registry auth, Kubernetes admission controller integration, etc.)

# 🤝 Contributing

(How others can contribute, open issues, PRs, coding style guidelines, etc.)
-->

# 📜 License
- Apache 2.0, see more details at [LICENSE File](./LICENSE).
