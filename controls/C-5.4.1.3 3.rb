# encoding: UTF-8

control "C-5.4.1.3" do
  title "Ensure password expiration warning days is 7 or more"
  desc  "The `PASS_WARN_AGE` parameter in `/etc/login.defs` allows an
administrator to notify users that their password will expire in a defined
number of days. It is recommended that the `PASS_WARN_AGE` parameter be set to
7 or more days."
  desc  "rationale", "Providing an advance warning that a password will be
expiring gives users time to think of a secure password. Users caught unaware
may choose a simple password or write it down where it may be discovered."
  desc  "check", "
    Run the following command and verify `PASS_WARN_AGE` conforms to site
policy (No less than 7 days):

    ```
    # grep PASS_WARN_AGE /etc/login.defs

    PASS_WARN_AGE 7
    ```

    Verify all users with a password have their number of days of warning
before password expires set to 7 or more:
    Run the following command and Review list of users and `PASS_WARN_AGE` to
verify that all users' `PASS_WARN_AGE` conforms to site policy (No less than 7
days):

    ```
    # grep -E ^[^:]+:[^\\!*] /etc/shadow | cut -d: -f1,6

    :

    ```
  "
  desc  "fix", "
    Set the `PASS_WARN_AGE` parameter to 7 in `/etc/login.defs` :

    ```
    PASS_WARN_AGE 7
    ```

    Modify user parameters for all users with a password set to match:

    ```
    # chage --warndays 7
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
  tag cis_rid: "5.4.1.3"
end
