# encoding: UTF-8

control "C-4.2.1.3" do
  title "Ensure logging is configured"
  desc  "The `/etc/rsyslog.conf` and `/etc/rsyslog.d/*.conf` files specifies
rules for logging and which files are to be used to log certain classes of
messages."
  desc  "rationale", "A great deal of important security-related information is
sent via `rsyslog` (e.g., successful and failed su attempts, failed login
attempts, root login attempts, etc.)."
  desc  "check", "
    Review the contents of the `/etc/rsyslog.conf` and `/etc/rsyslog.d/*.conf`
files to ensure appropriate logging is set. In addition, run the following
command and verify that the log files are logging information:

    ```
    # ls -l /var/log/
    ```
  "
  desc "fix", "
    Edit the following lines in the `/etc/rsyslog.conf` and
`/etc/rsyslog.d/*.conf` files as appropriate for your environment:

    ```
    *.emerg :omusrmsg:*
    auth,authpriv.* /var/log/auth.log
    mail.* -/var/log/mail
    mail.info -/var/log/mail.info
    mail.warning -/var/log/mail.warn
    mail.err /var/log/mail.err
    news.crit -/var/log/news/news.crit
    news.err -/var/log/news/news.err
    news.notice -/var/log/news/news.notice
    *.=warning;*.=err -/var/log/warn
    *.crit /var/log/warn
    *.*;mail.none;news.none -/var/log/messages
    local0,local1.* -/var/log/localmessages
    local2,local3.* -/var/log/localmessages
    local4,local5.* -/var/log/localmessages
    local6,local7.* -/var/log/localmessages
    ```

    Run the following command to reload the `rsyslog` configuration:

    ```
    # systemctl reload rsyslog
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["AU-12", "AU-3", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["6.2", "6.3", "Rev_7"]
  tag cis_rid: "4.2.1.3"
end
