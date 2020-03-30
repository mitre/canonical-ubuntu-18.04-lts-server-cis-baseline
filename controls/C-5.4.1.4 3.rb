# encoding: UTF-8

control "C-5.4.1.4" do
  title "Ensure inactive password lock is 30 days or less"
  desc  "User accounts that have been inactive for over a given period of time
can be automatically disabled. It is recommended that accounts that are
inactive for 30 days after password expiration be disabled."
  desc  "rationale", "Inactive accounts pose a threat to system security since
the users are not logging in to notice failed login attempts or other
anomalies."
  desc  "check", "
    Run the following command and verify `INACTIVE` conforms to sire policy (no
more than 30 days):

    ```
    # useradd -D | grep INACTIVE

    INACTIVE=30
    ```

    Verify all users with a password have Password inactive no more than 30
days after password expires:
    Run the following command and Review list of users and INACTIVE to verify
that all users' INACTIVE conforms to site policy (no more than 30 days):

    ```
    # grep -E ^[^:]+:[^\\!*] /etc/shadow | cut -d: -f1,7

    :
    ```
  "
  desc  "fix", "
    Run the following command to set the default password inactivity period to
30 days:

    ```
    # useradd -D -f 30
    ```

    Modify user parameters for all users with a password set to match:

    ```
    # chage --inactive 30
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
  tag nist: ["IA-5 (1)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["4.4", "Rev_7"]
  tag cis_rid: "5.4.1.4"
end
