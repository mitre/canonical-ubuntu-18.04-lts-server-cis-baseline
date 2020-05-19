# encoding: UTF-8

control "C-1.9" do
  title "Ensure updates, patches, and additional security software are
installed"
  desc  "Periodically patches are released for included software either due to
security flaws or to include additional functionality."
  desc  "rationale", "Newer patches may contain security enhancements that
would not be available through the latest full update. As a result, it is
recommended that the latest software patches be used to take advantage of the
latest functionality. As with any software installation, organizations need to
determine if a given update meets their requirements and verify the
compatibility and supportability of any additional software against the update
revision that is selected."
  desc  "check", "
    Verify there are no updates or patches to install:

    ```
    # apt -s upgrade
    ```
  "
  desc  "fix", "
    Use your package manager to update all packages on the system according to
site policy.

    Run the following command to update all packages following local site
policy guidance on applying updates and patches:

    ```
    # apt upgrade
    ```

    OR

    ```
    # apt dist-upgrade
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
  tag nist: ["SI-2", "SI-2", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["3.4", "3.5", "Rev_7"]
  tag cis_rid: "1.9"

  describe command('apt -s upgrade') do
    its('exit_status') { should cmp 0 }
    its('stdout') { should match '^0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.$' }
  end
end
