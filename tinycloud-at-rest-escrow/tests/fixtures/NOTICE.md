`piv_p256_plugin_0_5_1.age` was produced by the **released** age-plugin-yubikey
0.5.1 (crates.io, built `--locked`) through stock age v1.3.2:

```sh
printf 'tinycloud age-plugin-yubikey 0.5.1 piv-p256 vector' > msg.txt
age -e -a -r age1yubikey1qg3fps8csqk30gjdt552hf7jyjnmt753z9yhk4p8f0x5vvr5m53mju3vr5u -o piv_p256_plugin_0_5_1.age msg.txt
```

The recipient is a software TEST key, not a YubiKey. Its secret scalar is
`c2d3663dcc50dd691a502185a3f4de30f4c7ef664548414eca5c6a72790f36d2`. It exists
only so tests can check, with the plugin's own output, that the test identity
opens `piv-p256` stanzas exactly as the plugin does and rejects what it rejects.
