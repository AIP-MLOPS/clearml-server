# FROM node:20-bookworm-slim as webapp_builder
FROM docker.arvancloud.ir/library/node:20-bookworm-slim as webapp_builder

# Install Python and dependencies (required to run the patching script)
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

COPY docker/build/debian.sources /etc/apt/sources.list.d/debian.sources
COPY docker/build/pip.conf /etc/pip.conf

ARG GITHUB_TOKEN=
# ARG CLEARML_WEB_GIT_URL=https://github.com/allegroai/clearml-web.git
ARG CLEARML_WEB_GIT_URL=https://github.com/allegroai/clearml-web.git
# ARG CLEARML_WEB_GIT_URL=https://github.com/AIP-MLOPS/aip-web.git

USER root
WORKDIR /opt
# # Overwrite sources.list with ArvanCloud mirror
# RUN echo "deb http://mirror.arvancloud.ir/debian bookworm main contrib non-free" > /etc/apt/sources.list && \
#     echo "deb http://mirror.arvancloud.ir/debian-security bookworm-security main contrib non-free" >> /etc/apt/sources.list && \
#     echo "deb http://mirror.arvancloud.ir/debian bookworm-updates main contrib non-free" >> /etc/apt/sources.list
#RUN sleep 3

# Clone the ClearML repo
RUN apt-get update && apt-get install -y git
# RUN git clone ${CLEARML_WEB_GIT_URL} clearml-web
RUN git clone --branch clearml-web-login https://$GITHUB_TOKEN@github.com/AIP-MLOPS/tools.git clearml-web

RUN mv clearml-web /opt/open-webapp

# --- Copy the patcher folder (from docker/patcher) into the image ---
COPY docker/patcher /opt/clearml/patcher
# Run the branding patching script before the build
RUN python3 /opt/clearml/patcher/scripts/patch_repo.py \
  --logo-dir /opt/clearml/patcher/files/logos \
  --brand-name "aiplatform" \
  --links-json /opt/clearml/patcher/files/links.json \
  --style-file /opt/clearml/patcher/files/clearml-palette.scss

# --- Continue with webapp build ---
COPY --chmod=744 docker/build/internal_files/build_webapp.sh /tmp/internal_files/
RUN /bin/bash -c '/tmp/internal_files/build_webapp.sh'

# --- DEBUG STEP: Recursively list all created files in the builder ---
# RUN echo "--- [DEBUG] Listing all files in /opt/open-webapp/build/ before final COPY ---" && \
#     echo "---------------------------------------------------------------------"&& \
#     ls -la /opt/open-webapp/build/ && \
#     echo "---------------------------------------------------------------------"

##############
# WORKDIR /opt/open-webapp

# # Install dependencies using the command from your script
# # This makes the build process clearer and easier to debug
# RUN npm ci --legacy-peer-deps --registry="https://mirror-npm.runflare.com"

# # Build the main application and the widgets
# RUN npm run build
# RUN npm run build-widgets
# ########### 


# FROM python:3.9-slim-bookworm
FROM docker.arvancloud.ir/library/python:3.9-slim-bookworm

# Set environment variables
ENV CASDOOR_ENDPOINT="https://iam.ai-lab.ir"
ENV CASDOOR_CLIENT_ID=
ENV CASDOOR_CLIENT_SECRET=
ENV CASDOOR_ORG_NAME="organization_sharif"
ENV CASDOOR_APP_NAME="application_panel"

# COPY docker/build/casdoor_certificate.pem /app/casdoor_certificate.pem
# RUN export CASDOOR_CERTIFICATE=$(cat /app/casdoor_certificate.pem) && \
#     echo "CASDOOR_CERTIFICATE is set"
# RUN echo $(cat /app/casdoor_certificate.pem)

# RUN echo "certificate is  $CASDOOR_CERTIFICATE" 
# ENV CASDOOR_CERTIFICATE = "-----BEGIN CERTIFICATE----- MIIE3TCCAsWgAwIBAgIDAeJAMA0GCSqGSIb3DQEBCwUAMCgxDjAMBgNVBAoTBWFk bWluMRYwFAYDVQQDEw1jZXJ0LWJ1aWx0LWluMB4XDTI1MDcyMTA2MzA0MFoXDTQ1 MDcyMTA2MzA0MFowKDEOMAwGA1UEChMFYWRtaW4xFjAUBgNVBAMTDWNlcnQtYnVp bHQtaW4wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDNPOHzcM5jQzsQ 5MPitVbKckBhUVaJidlyZKdvAvMJSiNj7z1bmD4viiFRKiYdDgLs7ohQy/n6Dz+F 8aiIlT5SwWI/ERF/GfRqgr+dwIWixUrQBXdJ62O5vFDv36CnfXf9EvWoRYdCf/1U B87F8Bx+b9Sp75Q2+Z8/+xvZdQtOIBhMIFnBtJkFbEGFvGcR+GZX+SZpGAmzpjsH 2sTDpYc5bcWILY4mpQaihREKwB+KapSY+D74XAuXAjw5tqKgKuhSFGXx97NDmlYl pI+ZFdf42gvpyRw4rdLtgUkd8NDWd++BdkrxmOvAn94bGzHQmmbjlGxfP89oVEMK zPNPAgFabmW1EAsGripJroFreClzew4uU7bhWozlC3sj+aGo1KVu0M1JrY/zyxE0 EJvGF84oCxhrcH5nijVgbKR2MHcO7dVxbzgw/or24MBTCMSl6qc7NHW7gPYQosLv qLZCKdzT2QbkyiENp0UySVgF20O44NzwUj3zVAain6FGygyDV33hO1Lekqoj4o0P Y3vY/2DWY3g4NZuRG0o9E4FbYL0quwSWZdXw1iDCQvfGUER6CH+Pn2ICu66cnK9h A3GElh8A87bLXo3blbm99YpHtWCAlSeKjLj5RWjXGf4bYyh8SzbxqpKNspNatl5Q a9zOd9LG2GqlqPAGDpNXsmhsRhZ4QQIDAQABoxAwDjAMBgNVHRMBAf8EAjAAMA0G CSqGSIb3DQEBCwUAA4ICAQB1TU/kOeegk3OlC4DhC0h7+XfzgJRxV7LNigah+BzA HTj6AS9c5vDQQrLjz+mRSTNLeX2jZJCyp6x6kLcciJ5j2p9IAgMSXD5/vSTCoGh9 Y76av0PyQu6q/SOx7J5LB2VLqoBLPKJzz9/hMlGpnzywWkF6naYUd7YVSPpatKD/ 8SIZBQMS3OrFWcPqOhlt72d3ewPyyUeZvsWE7g3XbbrhESBQEgN1hbCbgRkiEZEv hRjfBywjGFo+TKJqX2mdWKxch5MEq1DwcbDqn7UCLVhWPmzjU+okBXxE4ZrT1xXa Wp3sxQyWQPdtVolY1amTh8Tzos92Jdztrxu9ZJnashTO9FBJRPD4osznWOAyvdVO GJ8oHQgN2KcYW+cAEWk6frI+hDzFt9aBnxDARPNg17mpBV6/z2Did4lRnjjb3cnl RMy4fvOZrFpA97oEEYSpchhX50Cjth4HMadIuk2RYoQaxpLZOYK7WPB1Dk6q33sf 2/BPI7oFfxSAhXTZcI3opGXBOTb6jSjHuuZZDdcDmUjLBLYxCTfpPL/FLQs24Ylf LYm7RYkKCpALClgcOtVbx+49yKQTjLBF2RkLpp9S5rjnVGpjfLzue2tbETbqL+df m9GxrMOM9/u6bkaU1zPEaOQZeJQ0FzYMS/1gEyEjW1WAotBxkz+VMcGh9STiO+Io 9w== -----END CERTIFICATE-----"


COPY docker/build/debian.sources /etc/apt/sources.list.d/debian.sources
COPY docker/build/pip.conf /etc/pip.conf
COPY --chmod=744 docker/build/internal_files/entrypoint.sh /opt/clearml/
COPY --chmod=744 docker/build/internal_files/update_from_env.py /opt/clearml/utilities/
COPY fileserver /opt/clearml/fileserver/
COPY apiserver /opt/clearml/apiserver/

COPY --chmod=744 docker/build/internal_files/final_image_preparation.sh /tmp/internal_files/
COPY docker/build/internal_files/clearml.conf.template /tmp/internal_files/
COPY docker/build/internal_files/clearml_subpath.conf.template /tmp/internal_files/
RUN /bin/bash -c '/tmp/internal_files/final_image_preparation.sh'

# --- DEBUG STEP: See what Nginx directory looks like BEFORE the copy ---
RUN echo "--- [DEBUG] Listing Nginx directory BEFORE copy ---" && \
    ls -la /usr/share/nginx/html/


COPY --from=webapp_builder /opt/open-webapp/build /usr/share/nginx/html
COPY --from=webapp_builder /opt/open-webapp/build/browser/ /usr/share/nginx/html

RUN echo "--- [DEBUG] Listing Nginx directory AFTER copy ---" && \
    sleep 10 && \
    ls /usr/share/nginx/ && \
    ls /usr/share/nginx/html/ && \
    echo "---------------------------------------------------------------------" 
    # sleep 150

COPY --from=webapp_builder /opt/open-webapp/dist/report-widgets /usr/share/nginx/widgets

# --- DEBUG STEP: See what Nginx directory looks like AFTER the copy ---

EXPOSE 8080
EXPOSE 8008
EXPOSE 8081

ARG VERSION
ARG BUILD
ENV CLEARML_SERVER_VERSION=${VERSION}
ENV CLEARML_SERVER_BUILD=${BUILD}

WORKDIR /opt/clearml/
ENTRYPOINT ["/opt/clearml/entrypoint.sh"]
