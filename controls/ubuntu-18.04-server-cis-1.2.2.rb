# encoding: UTF-8

control "C-1.2.2" do
  title "Ensure GPG keys are configured"
  desc  "Most packages managers implement GPG key signing to verify package
integrity during installation."
  desc  "rationale", "It is important to ensure that updates are obtained from
a valid source to protect against spoofing that could lead to the inadvertent
installation of malware on the system."
  desc  "check", "
    Verify GPG keys are configured correctly for your package manager:

    ```
    # apt-key list
    ```
Example.
 apt-key list
/etc/apt/trusted.gpg.d/ubuntu-keyring-2012-archive.gpg
------------------------------------------------------
pub   rsa4096 2012-05-11 [SC]
      790B C727 7767 219C 42C8  6F93 3B4F E6AC C0B2 1F32
uid           [ unknown] Ubuntu Archive Automatic Signing Key (2012) <ftpmaster@ubuntu.com>

/etc/apt/trusted.gpg.d/ubuntu-keyring-2012-cdimage.gpg
------------------------------------------------------
pub   rsa4096 2012-05-11 [SC]
      8439 38DF 228D 22F7 B374  2BC0 D94A A3F0 EFE2 1092
uid           [ unknown] Ubuntu CD Image Automatic Signing Key (2012) <cdimage@ubuntu.com>

/etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg
------------------------------------------------------
pub   rsa4096 2018-09-17 [SC]
      F6EC B376 2474 EDA9 D21B  7022 8719 20D1 991B C93C
uid           [ unknown] Ubuntu Archive Automatic Signing Key (2018) <ftpmaster@ubuntu.com>

  "
  desc "fix", "Update your package manager GPG keys in accordance with site
policy."
  impact 0.5
  tag severity: "medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["SI-2", "SI-2", "SI-7", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["3.4", "3.5", "4.5", "Rev_7"]
  tag cis_rid: "1.2.2"

  describe command('apt-key list').stdout.strip.split("\n") do
    its('length') { should be > 1 }
    skip "Run the following command and verify GPG keys are configured correctly for your package manager -
 ```apt-cache policy```."
  end

end
