# encoding: UTF-8

control "C-2.2.12" do
  title "Ensure Samba is not enabled"
  desc  "The Samba daemon allows system administrators to configure their Linux
systems to share file systems and directories with Windows desktops. Samba will
advertise the file systems and directories via the Server Message Block (SMB)
protocol. Windows desktop users will be able to mount these directories and
file systems as letter drives on their systems."
  desc  "rationale", "If there is no need to mount directories and file systems
to Windows systems, then this service can be deleted to reduce the potential
attack surface."
  desc  "check", "
    Run the following command to verify `Samba` is not enabled:

    ```
    # systemctl is-enabled smbd

    disabled
    ```

    Verify result is not \"enabled\".
  "
  desc  "fix", "
    Run the following command to disable `Samba`:

    ```
    # systemctl --now disable smbd
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
  tag cis_rid: "2.2.12"

  if package('samba').installed?
    describe service('smbd') do
      it { should_not be_enabled }
      it { should_not be_running }
    end
  else
    impact 0.0
    describe "The Samba Server package is not installed" do
      skip "The Samba Server package is not installed."
    end
  end
end
