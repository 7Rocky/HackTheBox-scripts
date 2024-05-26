# Hack The Box. Machines. Bizness

Machine write-up: https://7rocky.github.io/en/htb/bizness

### `ofbiz_exploit.sh`

This Bash script is based on [deserialization.sh](../Monitors/deserialization.sh) from [Monitors](../Monitors). Basically, this script exploits [CVE-2023-51467](https://nvd.nist.gov/vuln/detail/CVE-2023-51467) and [CVE-2023-49070](https://nvd.nist.gov/vuln/detail/CVE-2023-49070).

The only difference with [deserialization.sh](../Monitors/deserialization.sh) is that we need to add `?USERNAME=&PASSWORD=&requirePasswordChange=Y` for an authentication bypass and modify the way to call [ysoserial](https://github.com/frohoff/ysoserial). The rest is all the same.
