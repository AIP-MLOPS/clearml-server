# FROM node:20-bookworm-slim as webapp_builder
FROM docker.arvancloud.ir/library/node:20-bookworm-slim as webapp_builder

# Install Python and dependencies (required to run the patching script)
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

COPY docker/build/debian.sources /etc/apt/sources.list.d/debian.sources
COPY docker/build/pip.conf /etc/pip.conf
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
RUN git clone ${CLEARML_WEB_GIT_URL} clearml-web
RUN mv clearml-web /opt/open-webapp

# --- Copy the patcher folder (from docker/patcher) into the image ---
COPY docker/patcher /opt/clearml/patcher
# Run the branding patching script before the build
RUN python3 /opt/clearml/patcher/scripts/patch_repo.py \
  --logo-dir /opt/clearml/patcher/files/logos \
  --brand-name "aiplatform" \
  --links-json /opt/clearml/patcher/files/links.json \
  --style-file /opt/clearml/patcher/files/colors.scss

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
