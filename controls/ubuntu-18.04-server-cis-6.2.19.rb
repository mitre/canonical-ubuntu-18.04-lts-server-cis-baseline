# encoding: UTF-8

control "C-6.2.19" do
  title "Ensure no duplicate group names exist"
  desc  "Although the `groupadd` program will not let you create a duplicate
group name, it is possible for an administrator to manually edit the
`/etc/group` file and change the group name."
  desc  "rationale", "If a group is assigned a duplicate group name, it will
create and have access to files with the first GID for that group in
`/etc/group` . Effectively, the GID is shared, which is a security problem."
  desc  "check", "
    Run the following script and verify no results are returned:

    ```
    #!/bin/bash

    cut -d: -f1 /etc/group | sort | uniq -d | while read -r grp; do
     echo \"Duplicate group name \\\"$grp\\\" exists in /etc/group\"
    done
    ```
  "
  desc "fix", "Based on the results of the audit script, establish unique
names for the user groups. File group ownerships will automatically reflect the
change as long as the groups have unique GIDs."
  impact 0.5
  tag severity: "medium"
  tag nist: ["AC-2"]
  tag cis_level: 1
  tag cis_controls: ["16"]
  tag cis_cdc_version: "7"
  tag cis_rid: "6.2.19"

  groups.entries.each do |g|
    describe groups.where { name == g.name } do
      its('count') { should eq 1 }
    end
  end
end
