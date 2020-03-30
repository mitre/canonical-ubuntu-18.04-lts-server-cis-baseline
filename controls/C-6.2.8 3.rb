# encoding: UTF-8

control "C-6.2.8" do
  title "Ensure users' home directories permissions are 750 or more restrictive"
  desc  "While the system administrator can establish secure permissions for
users' home directories, the users can easily override these."
  desc  "rationale", "Group or world-writable user home directories may enable
malicious users to steal or modify other users' data or to gain another user's
system privileges."
  desc  "check", "
    Run the following script and verify no results are returned:

    ```
    #!/bin/bash

    grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 !=
\"'\"$(which nologin)\"'\" & do
     if [ ! -d \"$dir\" ]; then
     echo \"The home directory ($dir) of user $user does not exist.\"
     else
     dirperm=\"$(ls -ld \"$dir\" | cut -f1 -d\" \")\"
     if [ \"$(echo \"$dirperm\" | cut -c6)\" != \"-\" ]; then
     echo \"Group Write permission set on the home directory \\\"$dir\\\" of
user $user\"
     fi
     if [ \"$(echo \"$dirperm\" | cut -c8)\" != \"-\" ]; then
     echo \"Other Read permission set on the home directory \\\"$dir\\\" of
user $user\"
     fi
     if [ \"$(echo \"$dirperm\" | cut -c9)\" != \"-\" ]; then
     echo \"Other Write permission set on the home directory \\\"$dir\\\" of
user $user\"
     fi
     if [ \"$(echo \"$dirperm\" | cut -c10)\" != \"-\" ]; then
     echo \"Other Execute permission set on the home directory \\\"$dir\\\" of
user $user\"
     fi
     fi
    done
    ```
  "
  desc "fix", "Making global modifications to user home directories without
alerting the user community can result in unexpected outages and unhappy users.
Therefore, it is recommended that a monitoring policy be established to report
user file permissions and determine the action to be taken in accordance with
site policy."
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
  tag cis_rid: "6.2.8"
end
