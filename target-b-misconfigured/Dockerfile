# Target B - misconfigured Apache + PHP site
# Official PHP image that already includes Apache
FROM php:8.2-apache

# Replace Apache's security settings with our insecure version
COPY target-b-misconfigured/security.conf /etc/apache2/conf-available/security.conf

# Add our insecure PHP settings
COPY target-b-misconfigured/php.ini /usr/local/etc/php/conf.d/lab.ini

# Copy the sample website
COPY site/ /var/www/html/

# Copy the leftover files a careless developer forgot to delete
COPY target-b-misconfigured/leftovers/ /var/www/html/
