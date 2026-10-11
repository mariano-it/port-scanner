# Generar los logs que lee `portscan-detect`

Con UFW (más simple):

```bash
sudo ufw logging medium
sudo ufw enable
# los bloqueos quedan en el journal del kernel:
sudo journalctl -k --since "10 min ago" | grep 'UFW BLOCK' > ufw.log
portscan-detect ufw.log
```

Con iptables, registrando todo SYN entrante (solo en tu lab, genera mucho log):

```bash
sudo iptables -I INPUT -p tcp --syn -j LOG --log-prefix "SYN-IN: "
sudo journalctl -k -f | grep 'SYN-IN' > syn.log
```

Con Suricata, `eve.json` ya trae eventos `flow` que el detector entiende:

```bash
portscan-detect /var/log/suricata/eve.json --format eve
```
