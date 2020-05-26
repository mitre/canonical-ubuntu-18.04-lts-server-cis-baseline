# encoding: UTF-8

control "C-2.3.3" do
  title "Ensure talk client is not installed"
  desc  "The `talk` software makes it possible for users to send and receive
messages across systems through a terminal session. The `talk` client, which
allows initialization of talk sessions, is installed by default."
  desc  "rationale", "The software presents a security risk as it uses
unencrypted protocols for communication."
  desc  "check", "
    Verify `talk` is not installed. The following command may provide the
needed information:

    ```
    dpkg -s talk
    ```
  "
  desc "fix", "
    Uninstall `talk`:

    ```
    apt remove talk
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
  tag cis_rid: "2.3.3"

  describe package('talk') do
    it { should_not be_installed }
  end
end
