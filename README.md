# just_security_check
Just check for security vulnerabilities in your project using the security advisory database.

# Installation
```bash
composer require --dev onnov/just_security_check
```

# Usage security check
```bash
# run
php bin/just_security_check r

# if require-dev should be checked as well
php bin/just_security_check r -d

# if you need to allowed package vulnerabilities
php bin/just_security_check r -a symfony/symfony,twig/twig
```

# Usage max time check
```bash
# run
php bin/just_security_check t

# if require-dev should be checked as well
php bin/just_security_check t -d

# if need to allow a packet after the max time
php bin/just_security_check t -d -a amphp/process,unleash/client
docker compose exec php bin/just_security_check t -d -a psr/*

# if need to exclude a packet after the max time
php bin/just_security_check r -e amphp/process
php bin/just_security_check r -e vendor/*
php bin/just_security_check r -e vendor
```
