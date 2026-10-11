"""Scanner registry. Import a scanner module here to make it discoverable."""

from quantumtrace.scanners.base import Scanner, registry
from quantumtrace.scanners.binary.artifacts import BinaryArtifactScanner
from quantumtrace.scanners.cloud.aws import AwsCloudPostureScanner
from quantumtrace.scanners.code.source import SourceCodeScanner
from quantumtrace.scanners.config.server import ServerConfigScanner
from quantumtrace.scanners.keys.files import CertificateKeyScanner
from quantumtrace.scanners.network.pcap import PcapScanner
from quantumtrace.scanners.runtime.trace import RuntimeTraceScanner

registry.register(AwsCloudPostureScanner())
registry.register(SourceCodeScanner())
registry.register(PcapScanner())
registry.register(CertificateKeyScanner())
registry.register(ServerConfigScanner())
registry.register(BinaryArtifactScanner())
registry.register(RuntimeTraceScanner())

__all__ = ["Scanner", "registry"]
