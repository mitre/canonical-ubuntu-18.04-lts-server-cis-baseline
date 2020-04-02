# encoding: UTF-8

control "C-5.4.1.1" do
  title "Ensure password expiration is 365 days or less"
  desc  "The `PASS_MAX_DAYS` parameter in `/etc/login.defs` allows an
administrator to force passwords to expire once they reach a defined age. It is
recommended that the `PASS_MAX_DAYS` parameter be set to less than or equal to
365 days."
  desc  "rationale", "The window of opportunity for an attacker to leverage
compromised credentials or successfully compromise credentials via an online
brute force attack is limited by the age of the password. Therefore, reducing
the maximum age of a password also reduces an attacker's window of opportunity."
  desc  "check", "
    Run the following command and verify `PASS_MAX_DAYS` conforms to site
policy (no more than 365 days):

    ```
    # grep PASS_MAX_DAYS /etc/login.defs

    PASS_MAX_DAYS 365
    ```

    Run the following command and Review list of users and PASS_MAX_DAYS to
verify that all users' PASS_MAX_DAYS conforms to site policy (no more than 365
days):

    ```
    # grep -E '^[^:]+:[^!*]' /etc/shadow | cut -d: -f1,5

    :

    ```
  "
  desc  "fix", "
    Set the `PASS_MAX_DAYS` parameter to conform to site policy in
`/etc/login.defs` :

    ```
    PASS_MAX_DAYS 365
    ```

    Modify user parameters for all users with a password set to match:

    ```
    # chage --maxdays 365
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
  tag cis_rid: "5.4.1.1"
end
