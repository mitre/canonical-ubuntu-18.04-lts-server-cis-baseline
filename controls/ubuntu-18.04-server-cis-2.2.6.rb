# encoding: UTF-8

control "C-2.2.6" do
  title "Ensure LDAP server is not enabled"
  desc  "The Lightweight Directory Access Protocol (LDAP) was introduced as a
replacement for NIS/YP. It is a service that provides a method for looking up
information from a central database."
  desc  "rationale", "If the system will not need to act as an LDAP server, it
is recommended that the software be disabled to reduce the potential attack
surface."
  desc  "check", "
    Run the following command to verify `slapd` is not enabled:

    ```
    # systemctl is-enabled slapd

    disabled
    ```

    Verify result is not \"enabled\".
  "
  desc  "fix", "
    Run one of the following commands to disable `slapd`:

    ```
    # systemctl --now disable slapd
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
  tag nist: ["CM-7 (1)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["9.2", "Rev_7"]
  tag cis_rid: "2.2.6"

  if package('slapd').installed?
    describe service('slapd') do
      it { should_not be_enabled }
      it { should_not be_running }
    end
  else
    impact 0.0
    describe "The Lightweight Directory Access Protocol (LDAP) Server package is not installed" do
      skip "The Lightweight Directory Access Protocol (LDAP) Server package is not installed, this control is Not Applicable."
    end
  end
end
