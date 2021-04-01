# encoding: UTF-8

control "C-6.2.16" do
  title "Ensure no duplicate UIDs exist"
  desc  "Although the `useradd` program will not let you create a duplicate
User ID (UID), it is possible for an administrator to manually edit the
`/etc/passwd` file and change the UID field."
  desc  "rationale", "Users must be assigned unique UIDs for accountability and
to ensure appropriate access protections."
  desc  "check", "
    Run the following script and verify no results are returned:

    ```
    #!/bin/bash

    awk -F: '{print $3}' /etc/passwd | sort -n | uniq -c | while read -r uid; do
     [ -z \"$uid\" ] & then
     users=$(awk -F: '($3 == n) { print $1 }' n=\"$2\" /etc/passwd | xargs)
     echo \"Duplicate UID \\\"$2\\\": \\\"$users\\\"\"
     fi
    done
    ```
  "
  desc "fix", "Based on the results of the audit script, establish unique UIDs
and review all files owned by the shared UIDs to determine which UID they are
supposed to belong to."
  impact 0.5
  tag severity: "medium"
  tag nist: ["AC-2"]
  tag cis_level: 1
  tag cis_controls: ["16"]
  tag cis_cdc_version: "7"
  tag cis_rid: "6.2.16"

  passwd.entries.each do |user|
    describe passwd.uids(user.uid) do
      its('count') { should eq 1 }
    end
  end
end
