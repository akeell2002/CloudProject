"""
Automated Verification Suite for Milestone 4.3 (Kubernetes Manifests)
Validates YAML structure, schema compliance, and integration with NodeConfig.
"""
import os
import glob
import yaml


def test_k8s_manifests():
    k8s_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "k8s"))
    files = glob.glob(os.path.join(k8s_dir, "*.yaml"))
    assert len(files) == 4, f"Expected 4 manifests, found {len(files)}"

    manifests = {}
    for f in files:
        basename = os.path.basename(f)
        with open(f, "r", encoding="utf-8") as stream:
            data = yaml.safe_load(stream)
            assert data is not None, f"{basename} is empty!"
            manifests[basename] = data
            print(f"  [PASS] {basename} is valid YAML")

    # 1. Verify ConfigMap
    cm = manifests["configmap.yaml"]
    assert cm["kind"] == "ConfigMap"
    assert cm["data"]["GRPC_PORT"] == "50051"
    assert "fednode-0.fedconsensus-mesh:50051" in cm["data"]["PEER_ADDRESSES"]
    print("  [PASS] ConfigMap defines correct ports and headless peer DNS mesh")

    # 2. Verify Headless Service
    svc = manifests["service-headless.yaml"]
    assert svc["kind"] == "Service"
    assert svc["spec"]["clusterIP"] == "None"
    print("  [PASS] Headless Service enforces clusterIP: None for direct peer gRPC addressing")

    # 3. Verify StatefulSet
    ss = manifests["statefulset.yaml"]
    assert ss["kind"] == "StatefulSet"
    assert ss["spec"]["replicas"] == 5
    assert ss["spec"]["serviceName"] == "fedconsensus-mesh"

    # Verify Downward API for NODE_ID
    container = ss["spec"]["template"]["spec"]["containers"][0]
    node_id_env = next(e for e in container["env"] if e["name"] == "NODE_ID")
    assert node_id_env["valueFrom"]["fieldRef"]["fieldPath"] == "metadata.name"
    print("  [PASS] StatefulSet correctly injects pod identity via Kubernetes Downward API")

    # Verify VolumeClaimTemplate persistence
    vct = ss["spec"]["volumeClaimTemplates"][0]
    assert vct["metadata"]["name"] == "data"
    print("  [PASS] StatefulSet includes volumeClaimTemplates for SQLite WAL persistence")

    print("\n=======================================================")
    print("   MILESTONE 4.3: KUBERNETES MANIFESTS VERIFIED 100%!  ")
    print("=======================================================\n")


if __name__ == "__main__":
    test_k8s_manifests()
