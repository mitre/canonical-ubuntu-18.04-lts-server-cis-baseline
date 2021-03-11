# encoding: UTF-8

control "C-5.2.13" do
  title "Ensure only strong Ciphers are used"
  desc  "This variable limits the ciphers that SSH can use during
communication."
  desc  "rationale", "
    Weak ciphers that are used for authentication to the cryptographic module
cannot be relied upon to provide confidentiality or integrity, and system data
may be compromised

    The DES, Triple DES, and Blowfish ciphers, as used in SSH, have a birthday
bound of approximately four billion blocks, which makes it easier for remote
attackers to obtain cleartext data via a birthday attack against a
long-duration encrypted session, aka a \"Sweet32\" attack

    The RC4 algorithm, as used in the TLS protocol and SSL protocol, does not
properly combine state data with key data during the initialization phase,
which makes it easier for remote attackers to conduct plaintext-recovery
attacks against the initial bytes of a stream by sniffing network traffic that
occasionally relies on keys affected by the Invariance Weakness, and then using
a brute-force approach involving LSB values, aka the \"Bar Mitzvah\" issue

    The passwords used during an SSH session encrypted with RC4 can be
recovered by an attacker who is able to capture and replay the session

    Error handling in the SSH protocol; Client and Server, when using a block
cipher algorithm in Cipher Block Chaining (CBC) mode, makes it easier for
remote attackers to recover certain plaintext data from an arbitrary block of
ciphertext in an SSH session via unknown vectors

    The mm_newkeys_from_blob function in monitor_wrap.c, when an AES-GCM cipher
is used, does not properly initialize memory for a MAC context data structure,
which allows remote authenticated users to bypass intended ForceCommand and
login-shell restrictions via packet data that provides a crafted callback
address
  "
  desc  "check", "
    Run the following command and verify that output does not contain any of
the listed weak ciphers

    ```
    # sshd -T | grep ciphers
    ```

    Weak Ciphers:

    ```
    3des-cbc
    aes128-cbc
    aes192-cbc
    aes256-cbc
    arcfour
    arcfour128
    arcfour256
    blowfish-cbc
    cast128-cbc
    rijndael-cbc@lysator.liu.se
    ```
  "
  desc "fix", "
    Edit the `/etc/ssh/sshd_config` file add/modify the `Ciphers` line to
contain a comma separated list of the site approved ciphers

    Example:

    ```
    Ciphers
chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
    ```
  "
  impact 0.5
  tag severity: "medium"
  tag nist: ["SC-8"]
  tag cis_level: 1
  tag cis_controls: ["14.4"]
  tag cis_rid: "5.2.13"
  tag cis_scored: true
  tag cis_version: "2.0.1"
  tag cis_cdc_version: 7
  cfg = sshd_config
  describe cfg do
    describe 'it should have defined Ciphers' do
      subject { cfg.Ciphers }
        it { should_not be_empty }
    end
    its('Ciphers') { should_not include(
      '3des-cbc',
      'aes128-cbc',
      'aes192-cbc',
      'aes256-cbc',
      'arcfour',
      'arcfour128',
      'arcfour256',
      'blowfish-cbc',
      'cast128-cbc',
      'rijndael-cbc@lysator.liu.se') }
  end
end
