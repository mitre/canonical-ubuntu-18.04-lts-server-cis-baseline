# encoding: UTF-8

control "C-5.4.1.5" do
  title "Ensure all users last password change date is in the past"
  desc  "All users should have a password change date in the past."
  desc  "rationale", "If a users recorded password change date is in the future
then they could bypass any set password expiration."
  desc  "check", "
    Run the following command and verify nothing is returned

    ```
    # awk -F: '{print $1}' /etc/shadow | while read -r usr; do [[ $(date
--date=\"$(chage --list \"$usr\" | grep '^Last password change' | cut -d:
-f2)\" +%s) > $(date +%s) ]] & done
    ```
  "
  desc "fix", "Investigate any users with a password change date in the future
and correct them. Locking the account, expiring the password, or resetting the
password manually may be appropriate."
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
  tag cis_rid: "5.4.1.5"
end
