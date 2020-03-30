# encoding: UTF-8

control "C-4.2.1.5" do
  title "Ensure rsyslog is configured to send logs to a remote log host"
  desc  "The `rsyslog` utility supports the ability to send logs it gathers to
a remote log host running `syslogd(8)` or to receive messages from remote
hosts, reducing administrative overhead."
  desc  "rationale", "Storing log data on a remote host protects log integrity
from local attacks. If an attacker gains root access on the local system, they
could tamper with or remove log data that is stored on the local system"
  desc  "check", "
    Review the `/etc/rsyslog.conf` and `/etc/rsyslog.d/*.conf` files and verify
that logs are sent to a central host.

    ```
    # grep -E \"^[^#](\\s*\\S+\\s*)\\s*action\\(\" /etc/rsyslog.conf
/etc/rsyslog.d/*.conf | grep \"target=\"
    ```

    Output should include `target=`

    **OR**

    ```
    # grep -E \"^[^#]\\s*\\S+\\.\\*\\s+@\" /etc/rsyslog.conf
/etc/rsyslog.d/*.conf
    ```

    Output should include either the FQDN or the IP of the remote loghost
  "
  desc "fix", "
    Edit the `/etc/rsyslog.conf` and `/etc/rsyslog.d/*.conf` files and add one
of the following lines:

    Newer syntax:

    ```
     action(type=\"omfwd\" target=\"\" port=\"

    \t\" protocol=\"tcp\"
     action.resumeRetryCount=\"\"
     queue.type=\"linkList\" queue.size=\")
    ```

    **Example:**

    ```
    *.* action(type=\"omfwd\" target=\"192.168.2.100\" port\"514\"
protocol=\"tcp\"
     action.resumeRetryCount=\"100\"
     queue.type=\"linkList\" queue.size=\"1000\")
    ```

    Older syntax:

    ```
    *.* @@
    ```

    **Example:**

    ```
    *.* @@192.168.2.100
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
  tag nist: ["SI-4 (2)", "SI-4 (2)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["6.6", "6.8", "Rev_7"]
  tag cis_rid: "4.2.1.5"
end
