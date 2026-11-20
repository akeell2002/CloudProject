"""Tests for Kubernetes manifests under k8s/."""
import glob
import os
import unittest

import yaml


class TestKubernetesManifests(unittest.TestCase):
    def test_k8s_manifests(self):
        k8s_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "k8s"))
        files = glob.glob(os.path.join(k8s_dir, "*.yaml"))
        self.assertEqual(len(files), 4)

        manifests = {}
        for path in files:
            with open(path, "r", encoding="utf-8") as stream:
                data = yaml.safe_load(stream)
                self.assertIsNotNone(data)
                manifests[os.path.basename(path)] = data

        cm = manifests["configmap.yaml"]
        self.assertEqual(cm["kind"], "ConfigMap")
        self.assertEqual(cm["data"]["GRPC_PORT"], "50051")
        self.assertIn("fednode-0.fedconsensus-mesh:50051", cm["data"]["PEER_ADDRESSES"])

        svc = manifests["service-headless.yaml"]
        self.assertEqual(svc["kind"], "Service")
        self.assertEqual(svc["spec"]["clusterIP"], "None")

        ss = manifests["statefulset.yaml"]
        self.assertEqual(ss["kind"], "StatefulSet")
        self.assertEqual(ss["spec"]["replicas"], 5)
        self.assertEqual(ss["spec"]["serviceName"], "fedconsensus-mesh")

        container = ss["spec"]["template"]["spec"]["containers"][0]
        node_id_env = next(e for e in container["env"] if e["name"] == "NODE_ID")
        self.assertEqual(node_id_env["valueFrom"]["fieldRef"]["fieldPath"], "metadata.name")

        vct = ss["spec"]["volumeClaimTemplates"][0]
        self.assertEqual(vct["metadata"]["name"], "data")


if __name__ == "__main__":
    unittest.main()
