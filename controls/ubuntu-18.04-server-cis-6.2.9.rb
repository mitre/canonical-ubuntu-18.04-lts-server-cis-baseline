# encoding: UTF-8

control "C-6.2.9" do
  title "Ensure users own their home directories"
  desc  "The user home directory is space defined for the particular user to
set local environment variables and to store personal files."
  desc  "rationale", "Since the user is accountable for files stored in the
user home directory, the user must be the owner of the directory."
  desc  "check", "
    Run the following script and verify no results are returned:

    ```
    #!/bin/bash

    grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 !=
\"'\"$(which nologin)\"'\" & do
     if [ ! -d \"$dir\" ]; then
     echo \"The home directory \\\"$dir\\\" of user $user does not exist.\"
     else
     owner=$(stat -L -c \"%U\" \"$dir\")
     if [ \"$owner\" != \"$user\" ]; then
     echo \"The home directory \\\"$dir\\\" of user $user is owned by $owner.\"
     fi
     fi
    done
    ```
  "
  desc "fix", "Change the ownership of any home directories that are not owned
by the defined user to the correct user."
  impact 0.5
  tag severity: "medium"
  tag nist: ["AC-3 (3)"]
  tag cis_level: 1
  tag cis_controls: ["14.6"]
  tag cis_cdc_version: "7"
  tag cis_rid: "6.2.9"

  nologin = command("which nologin").stdout.strip
  
  passwd.where { user != 'halt' && user != 'sync' && user != 'shutdown' && shell != nologin }.entries.each do |user|
    describe file(user.home) do
      its('owner') { should eq user.user }
    end
  end
end
