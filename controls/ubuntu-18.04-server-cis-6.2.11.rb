# encoding: UTF-8

control "C-6.2.11" do
  title "Ensure no users have .forward files"
  desc  "The `.forward` file specifies an email address to forward the user's
mail to."
  desc  "rationale", "Use of the `.forward` file poses a security risk in that
sensitive data may be inadvertently transferred outside the organization. The
`.forward` file also poses a risk as it can be used to execute commands that
may perform unintended actions."
  desc  "check", "
    Run the following script and verify no results are returned:

    ```
    #!/bin/bash

    grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | awk -F: '($7 !=
\"'\"$(which nologin)\"'\" & do
     if [ ! -d \"$dir\" ]; then
     echo \"The home directory ($dir) of user $user does not exist.\"
     else
     if [ ! -h \"$dir/.forward\" ] & then
     echo \".forward file \\\"$dir/.forward\\\" exists\"
     fi
     fi
    done
    ```
  "
  desc "fix", "Making global modifications to users' files without alerting
the user community can result in unexpected outages and unhappy users.
Therefore, it is recommended that a monitoring policy be established to report
user `.forward` files and determine the action to be taken in accordance with
site policy."
  impact 0.5
  tag severity: "medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["CM-6", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["5.1", "Rev_7"]
  tag cis_rid: "6.2.11"
end
