# encoding: UTF-8

control "C-2.1.1" do
  title "Ensure xinetd is not installed"
  desc  "The eXtended InterNET Daemon (`xinetd`) is an open source super daemon
that replaced the original `inetd` daemon. The `xinetd` daemon listens for well
known services and dispatches the appropriate daemon to properly respond to
service requests."
  desc  "rationale", "If there are no `xinetd` services required, it is
recommended that the package be removed."
  desc  "check", "
    Run the following command to verify `xinetd` is not installed:

    ```
    # dpkg -s xinetd
    ```

    Verify result is:

    ```
    dpkg-query: package 'xinetd' is not installed and no information is
available
    Use dpkg --info (= dpkg-deb --info) to examine archive files,
    and dpkg --contents (= dpkg-deb --contents) to list their contents.
    ```
  "
  desc  "fix", "
    Run the following commands to remove `xinetd`:

    ```
    # apt purge xinetd
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
  tag cis_rid: "2.1.1"

  describe package("xinetd") do
    it { should_not be_installed }
  end

end
