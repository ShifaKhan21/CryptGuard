import sqlite3
from datetime import datetime

DB = r'z:\Hacknova Hackathon\new\CryptGuard\Packet_analyzer\beacon_history.db'
conn = sqlite3.connect(DB)
conn.row_factory = sqlite3.Row

print()
print('=' * 68)
print('  BEACON ALERTS (last 15):')
print('=' * 68)
alerts = conn.execute('SELECT * FROM beacon_alerts ORDER BY timestamp DESC LIMIT 15').fetchall()
if not alerts:
    print('  No alerts in DB yet.')
else:
    print(f'  {"PROCESS":<25} {"IP":<22} SCORE  VERDICT      SIGNALS')
    print('  ' + '-'*70)
    for a in alerts:
        ts = datetime.fromtimestamp(a['timestamp']).strftime('%H:%M:%S')
        print(f'  [{ts}] {a["process_name"]:<20} {a["destination_ip"]:<22} {a["beacon_score"]:>3}    {a["verdict"]:<12} {a["signals"]}')

t  = conn.execute('SELECT COUNT(*) FROM beacon_history').fetchone()[0]
al = conn.execute('SELECT COUNT(*) FROM beacon_alerts').fetchone()[0]
bc = conn.execute("SELECT COUNT(*) FROM beacon_alerts WHERE verdict='BEACON'").fetchone()[0]
su = conn.execute("SELECT COUNT(*) FROM beacon_alerts WHERE verdict='SUSPICIOUS'").fetchone()[0]
print()
print(f'  DB Records  : {t}')
print(f'  Total Alerts: {al}   (BEACON={bc}  SUSPICIOUS={su})')
print()
conn.close()
