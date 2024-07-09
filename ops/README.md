# Ops

```
# "aws login"
AWS_PROFILE=RnD_AdministratorAccess aws sso login

# "aws whoami"
AWS_PROFILE=RnD_AdministratorAccess aws sts get-caller-identity

# "pulumi login"
AWS_PROFILE=RnD_AdministratorAccess pulumi login s3://dbtrag-pulumi-state-backend

# "pulumi whoami"
AWS_PROFILE=RnD_AdministratorAccess pulumi whoami --verbose

# "pulumi up"
AWS_PROFILE=RnD_AdministratorAccess pulumi up
```

## SSH config
To avoid issues with changing fingerprints, you should add this config in your `.ssh/config` file:
```
Host dbtrag.rnd.ouihelp.fr
    StrictHostKeyChecking no
```
