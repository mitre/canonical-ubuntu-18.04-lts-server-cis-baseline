# encoding: UTF-8

control "C-6.2.15" do
  title "Ensure all groups in /etc/passwd exist in /etc/group"
  desc  "Over time, system administration errors and changes can lead to groups
being defined in `/etc/passwd` but not in `/etc/group` ."
  desc  "rationale", "Groups defined in the `/etc/passwd` file but not in the
`/etc/group` file pose a threat to system security since group permissions are
not properly managed."
  desc  "check", "
    Run the following script and verify no results are returned:

    ```
    #!/bin/bash

    awk -F: '{print $4}' /etc/passwd | while read -r gid; do
     if ! grep -E -q \"^.*?:[^:]*:$gid:\" /etc/group; then
     echo \"The group ID \\\"$gid\\\" does not exist in /etc/group\"
     fi
    done
    ```
  "
  desc "fix", "Analyze the output of the Audit step above and perform the
appropriate action to correct any discrepancies found."
  impact 0.5
  tag severity: "medium"
  tag nist: ["AC-2", "AC-2", "AC-2"]
  tag cis_level: 1
  tag cis_controls: ["16.6", "16.7", "16.8"]
  tag cis_cdc_version: "7"
  tag cis_rid: "6.2.15"

  # passwd.gids returns a list of strings, while groups.gids returns a list of integers
  all_gids = groups.gids.map { |gid| gid.to_s }

  describe passwd do
    its('gids') { should be_in all_gids }
  end
end
