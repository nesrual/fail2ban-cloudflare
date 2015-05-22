# fail2ban-cloudflare

Integrate Fail2ban with Cloudflare API to mitigate HTTP flooding attacks using Nginx and Roboo.

Requirements:

1. Nginx
2. Roboo (https://github.com/yuri-gushin/Roboo)
3. Fail2ban
4. A Cloudflare account (https://www.cloudflare.com/a/sign-up)

### Get your Cloudflare API Key

1. Signup to Cloudflare: https://www.cloudflare.com/a/sign-up

2. Go to https://www.cloudflare.com/a/account/my-account and select `View API Key`.

3. Setup your site(s) to use Cloudflare

### Configure Fail2ban

1. Install `Fail2ban` on the server running Nginx and Roboo. 

2. Add the `nginx-roboo.conf` file to your `filter.d` dir.

3. Add the `cloudflare.conf` file to your `action.d` dir.

4. Edit the `cloudflare.conf` file and set your `cloudflare_username` and `cloudflare_api_key` under the `[Init]` section (bottom of the file)

5. Add the following to your `jail.conf` file:

    ```
    [nginx-roboo]
    enabled   = true
    port      = all
    filter    = nginx-roboo
    banaction = cloudflare
    logpath   = /var/log/nginx/challenged.log
    maxretry  = 250
    ```

6. Restart `Fail2ban`

This will make `Fail2ban` monitor the file `/var/log/nginx/challenged.log` and each client with more than 250 challenge attempts will be banned using the `cloudflare` filter.

Bad clients will automatically be banned at Cloudflare instead of continiously hitting your server. After the defined `bantime` clients are automatically removed from the blacklist again.

It might be a good idea to whitelist the IP range of Cloudflare in `Fail2ban` using the `ignoreip` section. A current list of the IP ranges of Cloudflare can be found here: https://www.cloudflare.com/ips

NOTE: At the moment `Fail2ban` doesn't work with IPv6 so it might be a good idea to disable IPv6 support in the Cloudflare admin interface for each site you want to protect using Fail2ban.