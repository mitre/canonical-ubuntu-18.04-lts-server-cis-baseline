# encoding: UTF-8

control "C-6.2.3" do
  title "Ensure all users' home directories exist"
  desc  "Users can be defined in `/etc/passwd` without a home directory or with
a home directory that does not actually exist."
  desc  "rationale", "If the user's home directory does not exist or is
unassigned, the user will be placed in \"/\" and will not be able to write any
files or have local environment variables set."
  desc  "check", "
    Run the following script and verify no results are returned:

    ```
    #!/bin/bash
    grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 !=
\"'\"$(which nologin)\"'\" & do
     if [ ! -d \"$dir\" ]; then
     echo \"The home directory $dir of user $user does not exist.\"
     fi
    done
    ```
  "
  desc "fix", "If any users' home directories do not exist, create them and
make sure the respective user owns the directory. Users without an assigned
home directory should be removed or assigned a home directory as appropriate."
  impact 0.5
  tag severity: "medium"
  tag nist: ["CM-6"]
  tag cis_level: 1
  tag cis_controls: ["5.1"]
  tag cis_cdc_version: "7"
  tag cis_rid: "6.2.3"

  nologin = command("which nologin").stdout.strip

  passwd.where { user != 'halt' && user != 'sync' && user != 'shutdown' && shell != nologin }.entries.each do |user|
    describe file(user.home) do
      it { should exist }
      it { should be_directory }
    end
  end
end
