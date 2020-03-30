# encoding: UTF-8

control "C-6.2.14" do
  title "Ensure no users have .rhosts files"
  desc  "While no `.rhosts` files are shipped by default, users can easily
create them."
  desc  "rationale", "This action is only meaningful if `.rhosts` support is
permitted in the file `/etc/pam.conf` . Even though the `.rhosts` files are
ineffective if support is disabled in `/etc/pam.conf` , they may have been
brought over from other systems and could contain information useful to an
attacker for those other systems."
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
     for file in $dir/.rhosts; do
     if [ ! -h \"$file\" ] & then
     echo \".rhosts file in \\\"$dir\\\"\"
     fi
     done
     fi
    done
    ```
  "
  desc "fix", "Making global modifications to users' files without alerting
the user community can result in unexpected outages and unhappy users.
Therefore, it is recommended that a monitoring policy be established to report
user `.rhosts` files and determine the action to be taken in accordance with
site policy."
  impact 0.5
  tag severity: "medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["SC-28", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["16.4", "Rev_7"]
  tag cis_rid: "6.2.14"
end
