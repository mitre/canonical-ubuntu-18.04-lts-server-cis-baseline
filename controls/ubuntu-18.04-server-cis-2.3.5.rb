# encoding: UTF-8

control "C-2.3.5" do
  title "Ensure LDAP client is not installed"
  desc  "The Lightweight Directory Access Protocol (LDAP) was introduced as a
replacement for NIS/YP. It is a service that provides a method for looking up
information from a central database."
  desc  "rationale", "If the system will not need to act as an LDAP client, it
is recommended that the software be removed to reduce the potential attack
surface."
  desc  "check", "
    Verify that `ldap-utils` is not installed. Use the following command to
provide the needed information:

    ```
    # dpkg -s ldap-utils
    ```
  "
  desc "fix", "
    Uninstall `ldap-utils`:

    ```
    # apt purge ldap-utils
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
  tag nist: ["CM-2 (2)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["2.6", "Rev_7"]
  tag cis_rid: "2.3.5"

  describe package('ldap-utils') do
    it { should_not be_installed }
  end
end
