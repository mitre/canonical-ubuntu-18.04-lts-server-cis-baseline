# encoding: UTF-8

control "C-1.7.1.1" do
  title "Ensure AppArmor is installed"
  desc  "AppArmor provides Mandatory Access Controls."
  desc  "rationale", "Without a Mandatory Access Control system installed only
the default Discretionary Access Control system will be available."
  desc  "check", "
    Verify that AppArmor is installed:

    ```
    # dpkg -s apparmor apparmor-utils
    ```
  "
  desc "fix", "
    Install Apparmor.

    ```
    # apt install apparmor apparmor-utils
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
  tag nist: ["AC-3 (3)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["14.6", "Rev_7"]
  tag cis_rid: "1.7.1.1"

  describe package('apparmor') do
    it { should be_installed }
  end

  describe package('apparmor-utils') do
    it { should be_installed }
  end
end
