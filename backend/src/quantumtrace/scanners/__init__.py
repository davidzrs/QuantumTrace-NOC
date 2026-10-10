"""Scanner registry. Import a scanner module here to make it discoverable."""

from quantumtrace.scanners.base import Scanner, registry
from quantumtrace.scanners.cloud.aws import AwsCloudPostureScanner
from quantumtrace.scanners.code.source import SourceCodeScanner
from quantumtrace.scanners.network.pcap import PcapScanner

registry.register(AwsCloudPostureScanner())
registry.register(SourceCodeScanner())
registry.register(PcapScanner())

__all__ = ["Scanner", "registry"]
