# encoding: UTF-8

control "C-2.2.2" do
  title "Ensure X Window System is not installed"
  desc  "The X Window System provides a Graphical User Interface (GUI) where
users can have multiple windows in which to run programs and various add on.
The X Windows system is typically used on workstations where users login, but
not on servers where users typically do not login."
  desc  "rationale", "Unless your organization specifically requires graphical
login access via X Windows, remove it to reduce the potential attack surface."
  desc  "check", "
    Verify X Windows System is not installed:

    ```
    dpkg -l xserver-xorg*
    ```
  "
  desc "fix", "
    Remove the X Windows System packages:

    ```
    apt purge xserver-xorg*
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
  tag cis_rid: "2.2.2"

  describe package('xserver-xorg') do
    it { should_not be_installed }
  end

  describe package('xserver-xorg-core') do
    it { should_not be_installed }
  end


end
