# encoding: UTF-8

control "C-6.2.12" do
  title "Ensure no users have .netrc files"
  desc  "The `.netrc` file contains data for logging into a remote host for
file transfers via FTP."
  desc  "rationale", "The `.netrc` file presents a significant security risk
since it stores passwords in unencrypted form. Even if FTP is disabled, user
accounts may have brought over `.netrc` files from other systems which could
pose a risk to those systems."
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
     if [ ! -h \"$dir/.netrc\" ] & then
     echo \".netrc file \\\"$dir/.netrc\\\" exists\"
     fi
     fi
    done
    ```
  "
  desc "fix", "Making global modifications to users' files without alerting
the user community can result in unexpected outages and unhappy users.
Therefore, it is recommended that a monitoring policy be established to report
user `.netrc` files and determine the action to be taken in accordance with
site policy."
  impact 0.5
  tag severity: "medium"
  tag nist: ["SC-28"]
  tag cis_level: 1
  tag cis_controls: ["16.4"]
  tag cis_cdc_version: "7"
  tag cis_rid: "6.2.12"

  nologin = command("which nologin").stdout.strip
  
  passwd.where { user != 'halt' && user != 'sync' && user != 'shutdown' && shell != nologin }.entries.each do |user|
    describe file("#{user.home}/.netrc") do
      it { should_not exist }
    end
  end
end
