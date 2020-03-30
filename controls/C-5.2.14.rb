# encoding: UTF-8

control "C-5.2.14" do
  title "Ensure only strong MAC algorithms are used"
  desc  "This variable limits the types of MAC algorithms that SSH can use
during communication."
  desc  "rationale", "MD5 and 96-bit MAC algorithms are considered weak and
have been shown to increase exploitability in SSH downgrade attacks. Weak
algorithms continue to have a great deal of attention as a weak spot that can
be exploited with expanded computing power. An attacker that breaks the
algorithm could take advantage of a MiTM position to decrypt the SSH tunnel and
capture credentials and information"
  desc  "check", "
    Run the following command and verify that output does not contain any of
the listed weak MAC algorithms:

    ```
    # sshd -T | grep -i \"MACs\"
    ```

    Weak MAC algorithms:

    ```
    hmac-md5
    hmac-md5-96
    hmac-ripemd160
    hmac-sha1
    hmac-sha1-96
    umac-64@openssh.com
    umac-128@openssh.com
    hmac-md5-etm@openssh.com
    hmac-md5-96-etm@openssh.com
    hmac-ripemd160-etm@openssh.com
    hmac-sha1-etm@openssh.com
    hmac-sha1-96-etm@openssh.com
    umac-64-etm@openssh.com
    umac-128-etm@openssh.com
    ```
  "
  desc "fix", "
    Edit the `/etc/ssh/sshd_config` file and add/modify the MACs line to
contain a comma separated list of the site approved MACs

    Example:

    ```
    MACs
hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: nil
  tag gid: nil
  tag rid: nil
  tag stig_id: nil
  tag fix_id: nil
  tag cci: nil
  tag nist: ["SC-8", "SC-8", "Rev_4"]
  tag cis_level: 1
  tag cis_controls: ["14.4", "16.5", "Rev_7"]
  tag cis_rid: "5.2.14"
end
