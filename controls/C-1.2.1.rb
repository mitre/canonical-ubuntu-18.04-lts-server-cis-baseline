# encoding: UTF-8

control "C-1.2.1" do
  title "Ensure package manager repositories are configured"
  desc  "Systems need to have package manager repositories configured to ensure
they receive the latest patches and updates."
  desc  "rationale", "If a system's package repositories are misconfigured
important patches may not be identified or a rogue repository could introduce
compromised software."
  desc  "check", "
    Run the following command and verify package repositories are configured
correctly:

    ```
    # apt-cache policy
    ```
  "
  desc "fix", "Configure your package manager repositories according to site
policy."
  impact 0.5
  tag severity: "medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["SI-2", "SI-2", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["3.4", "3.5", "Rev_7"]
  tag cis_rid: "1.2.1"



    describe command('apt-cache policy').stdout.strip.split("\n") do
      its('length') { should be > 11 }
      skip "Run the following command and verify package repositories are configured
correctly - ```apt-cache policy```. Configure your package manager repositories according to site
policy."
    end




end
