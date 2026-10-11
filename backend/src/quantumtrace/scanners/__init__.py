"""Scanner registry. Import a scanner module here to make it discoverable."""

from quantumtrace.scanners.base import Scanner, registry
from quantumtrace.scanners.binary.artifacts import BinaryArtifactScanner
from quantumtrace.scanners.cloud.aws import AwsCloudPostureScanner
from quantumtrace.scanners.code.source import SourceCodeScanner
from quantumtrace.scanners.config.server import ServerConfigScanner
from quantumtrace.scanners.deps.manifests import DependencyManifestScanner
from quantumtrace.scanners.keys.files import CertificateKeyScanner
from quantumtrace.scanners.network.pcap import PcapScanner

registry.register(AwsCloudPostureScanner())
registry.register(SourceCodeScanner())
registry.register(PcapScanner())
registry.register(DependencyManifestScanner())
registry.register(CertificateKeyScanner())
registry.register(ServerConfigScanner())
registry.register(BinaryArtifactScanner())

__all__ = ["Scanner", "registry"]
