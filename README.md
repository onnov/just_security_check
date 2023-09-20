# just_security_check
Just check for security vulnerabilities in your project using the security advisory database.

# Installation
```bash
composer require --dev onnov/just_security_check
```

# Usage
```bash
# run
php bin/just_security_check r

# if require-dev should be checked as well
php bin/just_security_check r -d

# if need to ignore packageы vulnerabilities
php bin/just_security_check r -a symfony/symfony,doctrine/annotations
```
