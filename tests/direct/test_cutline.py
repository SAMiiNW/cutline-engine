from conftest import CONTRACT
import json


NODES = ['Ingress gateway', 'Job worker', 'Shared cache', 'Protected control plane']
EDGES = [[0, 1], [0, 2], [1, 3], [2, 3]]


def opened(vm, deploy, owner, responder):
    vm.sender = owner
    contract = deploy(CONTRACT)
    contract.register_grid('mesh-4', '0x' + responder.hex(), 'Regional service mesh', NODES, EDGES, [3])
    return contract


def telemetry(vm):
    vm.mock_web(r'sensor-a\.example', {'status': 200, 'body': 'Ingress integrity alert. Worker, cache and control plane responding.'})
    vm.mock_web(r'sensor-b\.example', {'status': 200, 'body': 'Second observation confirms ingress compromise; downstream services still responding.'})


def classification(vm, compromised=None, unknown=None):
    compromised = compromised or []
    unknown = unknown or []
    healthy = [index for index in range(len(NODES)) if index not in compromised and index not in unknown]
    vm.mock_llm(
        r'.*CutlineEngine telemetry classification.*',
        json.dumps({
            'healthy_indexes': healthy,
            'compromised_indexes': compromised,
            'unknown_indexes': unknown,
            'citations': [[0, 1] for _ in NODES],
        }),
    )


def inspect(contract):
    contract.inspect_telemetry('mesh-4', ['https://sensor-a.example/live', 'https://sensor-b.example/live'])


def test_parallel_paths_produce_minimum_cut(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = opened(direct_vm, direct_deploy, direct_alice, direct_bob)
    direct_vm.sender = direct_bob
    telemetry(direct_vm)
    classification(direct_vm, compromised=[0])
    inspect(contract)
    row = contract.get_grid('mesh-4')
    assert row['state'] == 'CUT_READY'
    assert row['exposure_paths'] == [[0, 2], [1, 3]]
    assert row['cut_edge_indexes'] == [0, 1]


def test_receipt_completes_containment_permissionlessly(direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie):
    contract = opened(direct_vm, direct_deploy, direct_alice, direct_bob)
    direct_vm.sender = direct_bob
    telemetry(direct_vm)
    classification(direct_vm, compromised=[0])
    inspect(contract)
    direct_vm.clear_mocks()
    telemetry(direct_vm)
    direct_vm.mock_web(r'receipt\.example', {'status': 200, 'body': 'Edges 0 and 1 were isolated at the gateway.'})
    direct_vm.mock_llm(r'.*CutlineEngine containment receipt inspection.*', '{"isolated_edge_indexes":[0,1],"failed_edge_indexes":[]}')
    direct_vm.sender = direct_charlie
    contract.confirm_cut('mesh-4', 'https://receipt.example/change-77')
    assert contract.get_grid('mesh-4')['state'] == 'CONTAINED'


def test_unknown_node_is_treated_as_risk(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = opened(direct_vm, direct_deploy, direct_alice, direct_bob)
    direct_vm.sender = direct_bob
    telemetry(direct_vm)
    classification(direct_vm, unknown=[1])
    inspect(contract)
    row = contract.get_grid('mesh-4')
    assert row['state'] == 'CUT_READY'
    assert row['cut_edge_indexes'] == [2]


def test_compromised_protected_node_is_breached(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = opened(direct_vm, direct_deploy, direct_alice, direct_bob)
    direct_vm.sender = direct_bob
    telemetry(direct_vm)
    classification(direct_vm, compromised=[3])
    inspect(contract)
    assert contract.get_grid('mesh-4')['state'] == 'BREACHED'


def test_only_responder_can_inspect(direct_vm, direct_deploy, direct_alice, direct_bob, direct_charlie):
    contract = opened(direct_vm, direct_deploy, direct_alice, direct_bob)
    direct_vm.sender = direct_charlie
    telemetry(direct_vm)
    classification(direct_vm, compromised=[0])
    with direct_vm.expect_revert('designated responder'):
        inspect(contract)


def test_validator_rejects_forged_node_status(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = opened(direct_vm, direct_deploy, direct_alice, direct_bob)
    telemetry(direct_vm)
    classification(direct_vm, compromised=[0])
    grid = contract.grids['MESH-4']
    result = contract._classify(grid, ['https://sensor-a.example/live', 'https://sensor-b.example/live'])
    assert direct_vm.run_validator(leader_result=result) is True
    forged = dict(result)
    forged['compromised_indexes'] = []
    forged['healthy_indexes'] = [0, 1, 2, 3]
    assert direct_vm.run_validator(leader_result=forged) is False


def test_duplicate_grid_and_bad_edge_fail(direct_vm, direct_deploy, direct_alice, direct_bob):
    contract = opened(direct_vm, direct_deploy, direct_alice, direct_bob)
    with direct_vm.expect_revert('unique grid id'):
        contract.register_grid('mesh-4', '0x' + direct_bob.hex(), 'Duplicate mesh', NODES, EDGES, [3])
    with direct_vm.expect_revert('valid non-self edge'):
        contract.register_grid('bad-grid', '0x' + direct_bob.hex(), 'Invalid self loop', NODES, [[0, 0], [1, 2]], [3])
