# Target C - hardened Apache + PHP site (same website as Target B)
FROM php:8.2-apache

# Turn on mod_headers so Apache can add security headers
RUN a2enmod headers

# Replace Apache's security settings with our hardened version
COPY target-c-hardened/security.conf /etc/apache2/conf-available/security.conf

# Add our hardened PHP settings
COPY target-c-hardened/php.ini /usr/local/etc/php/conf.d/lab.ini

# Copy ONLY the sample website - no leftover files
COPY site/ /var/www/html/
