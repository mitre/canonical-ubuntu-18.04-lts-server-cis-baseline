# encoding: UTF-8

control "C-2.2.10" do
  title "Ensure HTTP server is not enabled"
  desc  "HTTP or web servers provide the ability to host web site content."
  desc  "rationale", "Unless there is a need to run the system as a web server,
it is recommended that the package be deleted to reduce the potential attack
surface."
  desc  "check", "
    Run the following command to verify `apache` is not enabled:

    ```
    # systemctl is-enabled apache2

    disabled
    ```

    Verify result is not \"enabled\".
  "
  desc  "fix", "
    Run the following command to disable `apache`:

    ```
    # systemctl --now disable apache2
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
  tag cis_rid: "2.2.10"

  if package('apache2').installed? || package('nginx').installed?
    describe service('apache2') do
      it { should_not be_enabled }
      it { should_not be_running }
    end
    describe service('nginx') do
      it { should_not be_enabled }
      it { should_not be_running }
    end
  else
    impact 0.0
    describe "An HTTP Server package is not installed" do
      skip "An HTTP Server package is not installed."
    end
  end
end
