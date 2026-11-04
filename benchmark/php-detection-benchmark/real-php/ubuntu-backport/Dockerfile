# A distro-packaged PHP: the version number looks old, but the security fix is
# backported by the distro. This is the case official php:* images cannot model.
# Confirm the installed version after build:
#   docker run --rm <image> php -r 'echo PHP_VERSION,"\n";'
#   docker run --rm <image> sh -c 'dpkg -l | grep php'
FROM ubuntu:24.04
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       apache2 libapache2-mod-php php \
    && rm -rf /var/lib/apt/lists/* \
    && printf 'expose_php = On\n' > /etc/php/*/apache2/conf.d/zz-expose.ini || true
COPY --chmod=0644 index.php /var/www/html/index.php
EXPOSE 80
CMD ["apache2ctl", "-D", "FOREGROUND"]
