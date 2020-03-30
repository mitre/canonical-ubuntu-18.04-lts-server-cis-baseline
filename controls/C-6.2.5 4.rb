# encoding: UTF-8

control "C-6.2.5" do
  title "Ensure no legacy \"+\" entries exist in /etc/group"
  desc  "The character + in various files used to be markers for systems to
insert data from NIS maps at a certain point in a system configuration file.
These entries are no longer required on most systems, but may exist in files
that have been imported from other platforms."
  desc  "rationale", "These entries may provide an avenue for attackers to gain
privileged access on the system."
  desc  "check", "
    Run the following command and verify that no output is returned:

    ```
    # grep '^\\+:' /etc/group
    ```
  "
  desc "fix", "Remove any legacy '+' entries from `/etc/group` if they exist."
  impact 0.5
  tag severity: "medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["AC-2", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["16.2", "Rev_7"]
  tag cis_rid: "6.2.5"
end
