# encoding: UTF-8

control "C-5.4.1.2" do
  title "Ensure minimum days between password changes is  configured"
  desc  "The `PASS_MIN_DAYS` parameter in `/etc/login.defs` allows an
administrator to prevent users from changing their password until a minimum
number of days have passed since the last time the user changed their password.
It is recommended that `PASS_MIN_DAYS` parameter be set to 1 or more days."
  desc  "rationale", "By restricting the frequency of password changes, an
administrator can prevent users from repeatedly changing their password in an
attempt to circumvent password reuse controls."
  desc  "check", "
    Run the following command and verify `PASS_MIN_DAYS` conforms to site
policy (no less than 1 day):

    ```
    # grep PASS_MIN_DAYS /etc/login.defs

    PASS_MIN_DAYS 1
    ```

    Run the following command and Review list of users and PAS_MIN_DAYS to
Verify that all users' PAS_MIN_DAYS conforms to site policy (no less than 1
day):

    ```
    # grep -E ^[^:]+:[^\\!*] /etc/shadow | cut -d: -f1,4

    :

    ```
  "
  desc  "fix", "
    Set the `PASS_MIN_DAYS` parameter to 1 in `/etc/login.defs` :

    ```
    PASS_MIN_DAYS 1
    ```

    Modify user parameters for all users with a password set to match:

    ```
    # chage --mindays 1
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
  tag nist: ["AC-2", "IA-5 (1)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["16", "4.4", "Rev_6"]
  tag cis_rid: "5.4.1.2"
end
