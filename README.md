# fail2ban-cloudflare - for Cloudflare API V4

Integrate Fail2ban with Cloudflare API (V4) to mitigate HTTP flooding attacks using Nginx and Roboo.

Requirements:

1. Nginx
2. Roboo (https://github.com/yuri-gushin/Roboo)
3. Fail2ban
4. A Cloudflare account (https://www.cloudflare.com/a/sign-up)
5. Ruby 1.9.3 or later

### Get your Cloudflare API Key

1. Signup to Cloudflare: https://www.cloudflare.com/a/sign-up

2. Go to https://www.cloudflare.com/a/account/my-account and select `View API Key`.

3. Setup your site(s) to use Cloudflare

### Configure Fail2ban

1. Install `Fail2ban` on the server running Nginx and Roboo.

2. Add the `nginx-roboo.conf` file to your `filter.d` dir.

3. Add the `cloudflare.conf` file to your `action.d` dir.

4. Edit the `cloudflare_api_manager.rb` file and set your `CLOUDFLARE_USERNAME` and `CLOUDFLARE_API_KEY` (line 8 and 9).

5. Optional add any proxy information if you need to access Cloudflare via a proxy server (line 15 to 18).

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

6. Add the `cloudflare_api_manager.rb` script to a location accessible to the `fail2ban` user and set appropriate permissions. Remember that your Cloudflare API keys are stored in this script so handle with care!  

7. Verify that an IP is added to your Cloudflare firewall by banning an IP:

    ```
    /path/to/ruby /path/to/cloudflare_api_manager.rb ban 1.2.3.4
    ```

8. Verify that the IP is removed from your Cloudflare firewall by unbanning the IP:

    ```
    /path/to/ruby /path/to/cloudflare_api_manager.rb unban 1.2.3.4
    ```

9. Restart `Fail2ban`

This will make `Fail2ban` monitor the file `/var/log/nginx/challenged.log` and each client with more than 250 challenge attempts will be banned using the `cloudflare` filter.

Bad clients will automatically be banned (presented with a Google reCAPTCHA challenge) at Cloudflare instead of continuously hitting your server. After the defined `bantime` clients are automatically removed from the blacklist again.

It might be a good idea to whitelist the IP range of Cloudflare in `Fail2ban` using the `ignoreip` section. A current list of the IP ranges of Cloudflare can be found here: https://www.cloudflare.com/ips/

NOTE: At the moment `Fail2ban` doesn't work with IPv6 so it might be a good idea to disable IPv6 support in the Cloudflare admin interface for each site you want to protect using Fail2ban.
