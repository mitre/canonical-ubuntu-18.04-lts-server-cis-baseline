# encoding: UTF-8

control "C-1.6.3" do
  title "Ensure prelink is disabled"
  desc  "`prelink `is a program that modifies ELF shared libraries and ELF
dynamically linked binaries in such a way that the time needed for the dynamic
linker to perform relocations at startup significantly decreases."
  desc  "rationale", "The prelinking feature can interfere with the operation
of AIDE, because it changes binaries. Prelinking can also increase the
vulnerability of the system if a malicious user is able to compromise a common
library such as libc."
  desc  "check", "
    Verify `prelink` is not installed:

    ```
    # dpkg -s prelink
    ```
  "
  desc  "fix", "
    Run the following command to restore binaries to normal:

    ```
    # prelink -ua
    ```
    Uninstall `prelink` using the appropriate package manager or manual
installation:

    ```
    # apt purge prelink
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
  tag nist: ["AU-2", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["14.9", "Rev_7"]
  tag cis_rid: "1.6.3"

  describe package('prelink') do
    it { should_not be_installed }
  end

end
