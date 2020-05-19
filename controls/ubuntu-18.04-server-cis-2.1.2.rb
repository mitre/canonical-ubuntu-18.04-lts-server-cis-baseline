# encoding: UTF-8

control "C-2.1.2" do
  title "Ensure openbsd-inetd is not installed"
  desc  "The `inetd` daemon listens for well known services and dispatches the
appropriate daemon to properly respond to service requests."
  desc  "rationale", "If there are no `inetd` services required, it is
recommended that the daemon be removed."
  desc  "check", "
    Run the following command and verify `openbsd-inetd` is not installed:

    ```
    dpkg -s openbsd-inetd
    ```
  "
  desc  "fix", "
    Run the following command to uninstall `openbsd-inetd`:

    ```
    apt-get remove openbsd-inetd
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
  tag cis_rid: "2.1.2"

  describe package("openbsd-inetd") do
    it { should_not be_installed }
  end

end
