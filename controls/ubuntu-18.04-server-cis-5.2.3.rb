# encoding: UTF-8

control "C-5.2.3" do
  title "Ensure permissions on SSH public host key files are configured"
  desc  "An SSH public key is one of two files used in SSH public key
authentication. In this authentication method, a public key is a key that can
be used for verifying digital signatures generated using a corresponding
private key. Only a public key that corresponds to a private key will be able
to authenticate successfully."
  desc  "rationale", "If a public host key file is modified by an unauthorized
user, the SSH service may be compromised."
  desc  "check", "
    Run the following command and verify Access does not grant write or execute
permissions to group or other for all returned files

    ```
    # find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \\;

     File: ‘/etc/ssh/ssh_host_rsa_key.pub’
     Size: 382 Blocks: 8 IO Block: 4096 regular file
    Device: ca01h/51713d Inode: 8631758 Links: 1
    Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)
    Access: 2018-10-22 18:24:56.861750616 +0000
    Modify: 2018-10-22 18:24:56.861750616 +0000
    Change: 2018-10-22 18:24:56.881750616 +0000
     Birth: -
     File: ‘/etc/ssh/ssh_host_ecdsa_key.pub’
     Size: 162 Blocks: 8 IO Block: 4096 regular file
    Device: ca01h/51713d Inode: 8631761 Links: 1
    Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)
    Access: 2018-10-22 18:24:56.897750616 +0000
    Modify: 2018-10-22 18:24:56.897750616 +0000
    Change: 2018-10-22 18:24:56.917750616 +0000
     Birth: -
     File: ‘/etc/ssh/ssh_host_ed25519_key.pub’
     Size: 82 Blocks: 8 IO Block: 4096 regular file
    Device: ca01h/51713d Inode: 8631763 Links: 1
    Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)
    Access: 2018-10-22 18:24:56.945750616 +0000
    Modify: 2018-10-22 18:24:56.945750616 +0000
    Change: 2018-10-22 18:24:56.961750616 +0000
     Birth: -
    ```
  "
  desc  "fix", "
    Run the following commands to set permissions and ownership on the SSH host
public key files

    ```
    # find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod 0644
{} \\;
    ```

    ```
    # find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown
root:root {} \\;
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag nist: ["AC-3 (3)"]
  tag cis_level: 1
  tag cis_controls: ["14.6"]
  tag cis_rid: "5.2.3"
  tag cis_scored: true
  tag cis_version: "2.0.1"
  tag cis_cdc_version: 7
  if inspec.directory('/etc/ssh').exist?
    find_command = command("find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub'").stdout.lines
    unless find_command.empty?
      find_command.each do |key_file|
        describe file(key_file.chomp) do
          it { should be_file }
          it { should be_owned_by 'root' }
          it { should be_grouped_into 'root' }
          it { should_not be_more_permissive_than('00644') }
        end
      end
    else 
      descibe "No 'ssh_host_*_key.pub' files were found in '/etc/ssh'" do 
        skip "You must validate this control manually or correct your sshd config"
      end
    end
  else
    descibe "'/etc/ssh' does not seem to exist, you must check this control by hand" do
      skip '/etc/ssh did not exist, please check this control by hand'
    end
  end
end
