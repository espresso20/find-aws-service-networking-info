# find-aws-service-networking-info

run with `python find_service_ips.py`

outputs each region under `regions = ["us-east-1", "us-west-2"]` into a csv file with the follwing key headings,

| Service | Public IP | Private IP | DNS Name | Name Tag | Environment | Other Tags | Worker Name Tag | Worker Other Tags |
|---------|-----------|------------|----------|----------|-------------|------------|-----------------|-------------------|

`profile = "your-aws-profile-here"` handles your AWS login profile. `aws sso loging --profile <my-profile>` or any other profile in your `~/.aws/config` file

