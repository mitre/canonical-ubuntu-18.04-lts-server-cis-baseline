# encoding: UTF-8

control "C-2.3.4" do
  title "Ensure telnet client is not installed"
  desc  "The `telnet` package contains the `telnet` client, which allows users
to start connections to other systems via the telnet protocol."
  desc  "rationale", "The `telnet` protocol is insecure and unencrypted. The
use of an unencrypted transmission medium could allow an unauthorized user to
steal credentials. The `ssh` package provides an encrypted session and stronger
security and is included in most Linux distributions."
  desc  "check", "
    Verify `telnet` is not installed. Use the following command to provide the
needed information:

    ```
    # dpkg -s telnet
    ```
  "
  desc "fix", "
    Uninstall `telnet`:

    ```
    # apt purge telnet
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
  tag nist: ["IA-2 (1)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["4.5", "Rev_7"]
  tag cis_rid: "2.3.4"

  describe package('telnet') do
    it { should_not be_installed }
  end
end
