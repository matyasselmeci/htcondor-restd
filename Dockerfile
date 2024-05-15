ARG BASE_IMAGE=htcondor/mini
FROM ${BASE_IMAGE}
LABEL org.opencontainers.image.title="HTCondor REST Daemon dev/test image"
LABEL org.opencontainers.image.vendor=""


# If we have a new binary build of HTCondor in a repo and it is bind-mounted
# to /localrepo, we can use it to upgrade the HTCondor in the image.

RUN if [ -d /localrepo ]; then \
        echo $'\
[local] \n\
name=Local \n\
baseurl=file:///localrepo/ \n\
enabled=1 \n\
priority=1 \n\
skip_if_unavailable=1 \n\
gpgcheck=0' > /etc/yum.repos.d/local.repo && \
        yum upgrade -y '*condor*'; \
        yum clean all; \
    fi

RUN mkdir -p /usr/local/src
RUN install -d -o restd -g restd /usr/local/src/htcondor-restd
COPY --chown=restd . /usr/local/src/htcondor-restd/
# Check how the RESTD was installed into the minicondor image.
# If the RESTD has been installed in a virtualenv owned by the restd user, then
# we need to install the new version in the same virtualenv.
# Otherwise, we install the new version as root.
RUN if [ -e /home/restd/htcondor-restd/bin/activate ]; then \
        runuser restd bash -c " \
            . /home/restd/htcondor-restd/bin/activate && \
            python3 -mpip install --upgrade /usr/local/src/htcondor-restd \
        "; \
    else \
        $(command -v pip-3 || command -v pip3) install --upgrade /usr/local/src/htcondor-restd; \
    fi

# Add some submit users for the user pool
RUN for n in 1 2 3 4; do \
        user=submituser$n; \
        useradd -m $user && \
        mkdir -p ~$user/.condor/tokens.d && \
        chmod 0700 ~$user/.condor/tokens.d && \
        echo 'SEC_CLIENT_AUTHENTICATION_METHODS = IDTOKENS' > ~$user/.condor/user_config && \
        chown -R ${user}: ~$user; \
    done

# Give the RESTD permissions to create a login account for the submit users. \
RUN echo $'\
SCHEDD_LOGIN_ACCOUNTS = submituser1 submituser2 submituser3 submituser4\n\
ALLOW_ADMINISTRATOR = $(ALLOW_ADMINISTRATOR) restd@$(FULL_HOSTNAME)\n\
' >> /etc/condor/config.d/10-placement-tokens.conf
