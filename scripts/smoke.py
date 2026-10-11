import json
import re
import time
from pathlib import Path

from genlayer_py import create_account, create_client
from genlayer_py.chains import studionet
from genlayer_py.types import TransactionStatus


ROOT = Path(__file__).parents[1]
ENV = (ROOT.parents[3] / 'accounts.env').read_text()
DEPLOYMENT = json.loads((ROOT / 'deployment.json').read_text())
ADDRESS = DEPLOYMENT['contractAddress']
COMMIT = DEPLOYMENT['sourceCommit']


def account(number):
    key = re.search(rf'^ACCOUNT_{number}_GENLAYER_PRIVATE_KEY\s*=\s*"?([^"\r\n]+)', ENV, re.M).group(1).strip()
    return create_account(account_private_key=key)


def client(number):
    return create_client(chain=studionet, account=account(number))


def write(number, name, args):
    active = client(number)
    tx = active.write_contract(address=ADDRESS, function_name=name, args=args)
    print(name + '_tx=' + str(tx), flush=True)
    receipt = active.wait_for_transaction_receipt(
        transaction_hash=tx,
        status=TransactionStatus.FINALIZED,
        retries=180,
        interval=5000,
        full_transaction=True,
    )
    leader = (receipt.get('consensus_data', {}).get('leader_receipt') or [{}])[0]
    assert receipt.get('result_name') == 'MAJORITY_AGREE'
    assert leader.get('execution_result') == 'SUCCESS'
    return str(tx)


nodes = ['Ingress gateway', 'Job worker', 'Shared cache', 'Protected control plane']
edges = [[0, 1], [0, 2], [1, 3], [2, 3]]
raw = f'https://raw.githubusercontent.com/SAMiiNW/cutline-engine/{COMMIT}/evidence'
cdn = f'https://cdn.jsdelivr.net/gh/SAMiiNW/cutline-engine@{COMMIT}/evidence'
github = f'https://github.com/SAMiiNW/cutline-engine/raw/{COMMIT}/evidence'
grid_id = 'MESH-' + str(int(time.time()))
transactions = {}
transactions['register'] = write(1, 'register_grid', [
    grid_id,
    account(2).address,
    'Regional service mesh',
    nodes,
    edges,
    [3],
])
transactions['inspect'] = write(2, 'inspect_telemetry', [
    grid_id,
    [raw + '/sensor-a.md', cdn + '/sensor-b.md'],
])
planned = client(1).read_contract(address=ADDRESS, function_name='get_grid', args=[grid_id])
assert planned['state'] == 'CUT_READY'
assert planned['cut_edge_indexes'] == [0, 1]
transactions['confirm'] = write(1, 'confirm_cut', [grid_id, github + '/containment-receipt.md'])
state = client(1).read_contract(address=ADDRESS, function_name='get_grid', args=[grid_id])
assert state['state'] == 'CONTAINED'
assert state['isolated_edge_indexes'] == [0, 1]
proof = {
    'gridId': grid_id,
    'transactions': transactions,
    'state': state,
    'disclosure': 'Telemetry, receipt, and configured wallets are operator-controlled technical fixtures.',
}
(ROOT / 'evidence' / 'live-proof.json').write_text(json.dumps(proof, indent=2) + '\n')
print(json.dumps(proof, indent=2), flush=True)
