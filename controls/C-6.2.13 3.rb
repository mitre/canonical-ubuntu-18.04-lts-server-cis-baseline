# encoding: UTF-8

control "C-6.2.13" do
  title "Ensure users' .netrc Files are not group or world accessible"
  desc  "While the system administrator can establish secure permissions for
users' `.netrc` files, the users can easily override these."
  desc  "rationale", "`.netrc `files may contain unencrypted passwords that may
be used to attack other systems."
  desc  "check", "
    Run the following script and verify no results are returned:

    ```
    #!/bin/bash

    grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | awk -F: '($7 !=
\"'\"$(which nologin)\"'\" & do
     if [ ! -d \"$dir\" ]; then
     echo \"The home directory \\\"$dir\\\" of user \\\"$user\\\" does not
exist.\"
     else
     for file in $dir/.netrc; do
     if [ ! -h \"$file\" ] & then
     fileperm=\"$(ls -ld \"$file\" | cut -f1 -d\" \")\"
     if [ \"$(echo \"$fileperm\" | cut -c5)\" != \"-\" ]; then
     echo \"Group Read set on \\\"$file\\\"\"
     fi
     if [ \"$(echo \"$fileperm\" | cut -c6)\" != \"-\" ]; then
     echo \"Group Write set on \\\"$file\\\"\"
     fi
     if [ \"$(echo \"$fileperm\" | cut -c7)\" != \"-\" ]; then
     echo \"Group Execute set on \\\"$file\\\"\"
     fi
     if [ \"$(echo \"$fileperm\" | cut -c8)\" != \"-\" ]; then
     echo \"Other Read set on \\\"$file\\\"\"
     fi
     if [ \"$(echo \"$fileperm\" | cut -c9)\" != \"-\" ]; then
     echo \"Other Write set on \\\"$file\\\"\"
     fi
     if [ \"$(echo \"$fileperm\" | cut -c10)\" != \"-\" ]; then
     echo \"Other Execute set on \\\"$file\\\"\"
     fi
     fi
     done
     fi
    done
    ```
  "
  desc "fix", "Making global modifications to users' files without alerting
the user community can result in unexpected outages and unhappy users.
Therefore, it is recommended that a monitoring policy be established to report
user `.netrc` file permissions and determine the action to be taken in
accordance with site policy."
  impact 0.5
  tag severity: "medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["AC-3 (3)", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["14.6", "Rev_7"]
  tag cis_rid: "6.2.13"
end
