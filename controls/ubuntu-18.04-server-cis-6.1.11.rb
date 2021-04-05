# encoding: UTF-8

control "C-6.1.11" do
  title "Ensure no unowned files or directories exist"
  desc  "Sometimes when administrators delete users from the password file they
neglect to remove all files owned by those users from the system."
  desc  "rationale", "A new user who is assigned the deleted user's user ID or
group ID may then end up \"owning\" these files, and thus have more access on
the system than was intended."
  desc  "check", "
    Run the following command and verify no files are returned:

    ```
    # df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}'
-xdev -nouser
    ```

    The command above only searches local filesystems, there may still be
compromised items on network mounted partitions. Additionally the `--local`
option to `df` is not universal to all versions, it can be omitted to search
all filesystems on a system including network mounted filesystems or the
following command can be run manually for each partition:

    ```
    # find

    \t -xdev -nouser
    ```
  "
  desc "fix", "Locate files that are owned by users or groups not listed in
the system configuration files, and reset the ownership of these files to some
active user on the system as appropriate."
  impact 0.5
  tag severity: "medium"
  tag nist: ["CM-8 (3)"]
  tag cis_level: 1
  tag cis_controls: ["13.2"]
  tag cis_cdc_version: "7"
  tag cis_rid: "6.1.11"

  describe command("df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nouser") do
    its('stdout') { should be_empty }
  end
end
