import copy
import re
import subprocess
from operator import itemgetter
from pathlib import Path

from Scripts import shared
from base import BaseUSBMap


def quick_read(path: Path):
    return path.read_text().strip("\x00").strip()


def quick_read_2(path: Path, name: str):
    return quick_read(path / name)


def find_parent_pci_controller(node: Path) -> str:
    """
    Walks up the directory tree until it lands in a directory that looks like the PCI address of the device something
    is attached to.
    @param node: path of a subdevice (of a PCI device) to find the PCI address to
    @return: PCI address as str, or "ParentPciControllerNotFound" when reaching /sys
    """
    while not re.match(r"[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}.[0-9a-fA-F]", node.name):
        if str(node.parent) != "/sys":  # don't leave /sys
            node = node.parent
        else:
            return "ParentPciControllerNotFound"
    return node.name


def get_acpi_name_from_path(peer_port: Path, bus_port_regex: str):
    """
    Returns ACPI name for given usb controller path.
    @param peer_port: Path to usb controller in sysfs
    @param bus_port_regex: regex to extract port number from path name, as fallback.
    @return:
    """
    return quick_read_2(peer_port, "firmware_node/path").split(".")[-1] \
        if (peer_port / "firmware_node/path").exists() \
        else f"Port {int(re.sub(bus_port_regex, '', peer_port.name))}"

def usbdevicespeed_from_speed(speed):
    if speed == 1.5:
        return shared.USBDeviceSpeeds.LowSpeed
    elif speed == 12:
        return shared.USBDeviceSpeeds.FullSpeed
    elif speed == 480:
        return shared.USBDeviceSpeeds.HighSpeed
    elif speed == 5000:
        return shared.USBDeviceSpeeds.SuperSpeed
    elif speed == 10000:
        return shared.USBDeviceSpeeds.SuperSpeedPlus
    else:
        return shared.USBDeviceSpeeds.Unknown


class LinuxUSBMap(BaseUSBMap):
    def __init__(self):
        # Initialize usb ids, try from known locations first.
        self.usb_names = None
        if self.parse_usbids_file('/usr/share/hwdata/usb.ids'):  # Most distros seem to use this path
            pass
        elif self.parse_usbids_file('/var/lib/usbutils/usb.ids'):  # At least Mint also has it here
            pass
        else:  # Try downloading it from linux-usb.org
            try:
                import urllib.request
                local_usbids = shared.current_dir / Path("usb.ids")
                urllib.request.urlretrieve('http://www.linux-usb.org/usb.ids', local_usbids)  # http only :/
                self.parse_usbids_file(local_usbids)
            except:
                print("Failed to download usb.ids, usb devices won't have names :(")
                pass
        super().__init__()

    def get_usb_name(self, vid: str, pid: str):
        """
        Returns the name of the usb device from the database for given Vendor-/Product ID
        @param vid: Vendor ID
        @param pid: Product ID
        @return: USB device name
        """
        if self.usb_names is not None:
            if (vid, pid) in self.usb_names:
                return f"{self.usb_names[(vid, pid)]} ({vid}:{pid})"
        return f"Unknown device ({vid}:{pid})"

    def get_usb_name_2(self, base_path: Path):
        """
        Fetches VID/PID for the given usb device (path) and returns its name.
        @param base_path: path to usb device in sysfs
        @return: USB device name.
        """
        if (vid_file := base_path / Path("idVendor")).exists() and (pid_file := base_path / Path("idProduct")).exists():
            try:
                vid = quick_read(vid_file)
                pid = quick_read(pid_file)
                return self.get_usb_name(vid, pid)
            except IOError:
                pass
        return f"Unknown device ({base_path})"

    def parse_usbids_file(self, file_path: str) -> bool:
        """
        Parses the usb.ids file to (vid,pid) -> vendor name + device name mapping to self.usb_names dict
        :return: bool -> whether parsing the file was successful
        """
        try:
            with open(file_path, 'r', errors='ignore') as usbids_file:
                vendor_line_regex = re.compile(r"^([0-9a-f]{4})  (.*)$")
                device_line_regex = re.compile(r"^\t([0-9a-f]{4})  (.*)$")
                other_lists_regex = re.compile(r"^[A-Z].*$")
                cur_vid = ""
                cur_vendor = ""
                self.usb_names = {}
                for line in usbids_file:
                    if line.startswith('#') or line == "\n":  # Skip "header" at beginning
                        continue
                    elif m := vendor_line_regex.match(line):  # Found a new vendor
                        cur_vid = m.group(1)
                        cur_vendor = m.group(2)
                    elif m := device_line_regex.match(line):  # Found a device for (last) vendor
                        self.usb_names[(cur_vid, m.group(1))] = f"{cur_vendor} {m.group(2)}"
                    elif other_lists_regex.match(line):  # Reached other lists in usb.ids -> stop parsing!
                        break
                return True
        except IOError:
            return False

    def enumerate_hub(self, hub: Path):
        bus_number = quick_read_2(hub, "busnum")
        hub_info = {
            "hub_name": hub.parent.name,  # The name of the parent directory is the name of the hub, as for root hubs,
            # an XHCI controller can contain two usb[0-9]+ root hubs?. For attached usb
            # hubs, they will get called with a path like usb3-port6/device, so the usb
            # port they are attached to is a unique name for this "attached" hub.
            "port_count": int(quick_read_2(hub, "maxchild")),
            "speed": usbdevicespeed_from_speed(int(quick_read_2(hub, "speed"))),
            "version": quick_read_2(hub, "version"),
            "ports": [],
        }

        # Get the ports
        ports = hub.glob(f"{bus_number}-*:1.0/*{bus_number}*-port*")
        bus_port_regex = r"^(?:usb)?" + re.escape(bus_number) + r"(?:-[0-9]+)?-port"  # To get number from port name
        for i, port in enumerate(sorted(ports, key=lambda x: int(re.sub(bus_port_regex, "", x.name)))):
            port_index = int(quick_read(firmware_address_file), 16) \
                if (firmware_address_file := port / "firmware_node/adr").exists() \
                else int(re.sub(bus_port_regex, "", port.name))

            port_info = {
                "name": get_acpi_name_from_path(port, bus_port_regex),
                "comment": None,
                "index": port_index,  # read from ACPI if it's a root hub, use number if it's an auxiliary hub
                "class": hub_info["speed"],  # tbd
                "type": None,
                "guessed": None,  # tbd
                "connect_type": quick_read_2(port, "connect_type"),
                "devices": [],
                "type_c": False,
                "path": str(port),
            }

            if (peer_port := (port / "peer")).exists():
                # Linux knows this port belongs to another! Hooray!
                peer_port = peer_port.resolve()
                port_info["companion_info"] = {"hub": find_parent_pci_controller(peer_port),
                                               "port": get_acpi_name_from_path(peer_port, bus_port_regex)}
                # Could maybe completely use ACPI paths for matching up companion ports...
            else:
                port_info["companion_info"] = {"hub": "", "port": ""}

            if (port / "connector").exists():
                # I think this is only USB-C
                port_info["type_c"] = True
                other_ports = [i for i in (port / "connector").glob("usb*-port*") if i.resolve() != port.resolve()]
                assert len(other_ports) == 1
                if (port / "peer").exists():  # TODO: Verify/Make things work with usb-c ports!
                    assert port_info["companion_info"] == re.match(r"(?P<hub>usb\d+)-port(?P<port>\d+)",
                                                                   other_ports[0].resolve().name).groupdict()
                port_info["companion_info"] = re.match(r"(?P<hub>usb\d+)-port(?P<port>\d+)",
                                                       other_ports[0].resolve().name).groupdict()

            if (device := (port / "device")).exists():
                device_info = {
                    "name": self.get_usb_name_2(device),
                    "speed": usbdevicespeed_from_speed(int(quick_read_2(device, "speed"))),
                    "devices": [],
                }

                if int(quick_read_2(device, "bDeviceClass"), 16) == 9:
                    # This is a hub. Enumerate devices, and add them as subdevices to the hub device.
                    for subdev in self.enumerate_hub(device)["ports"]:
                        device_info["devices"] += subdev["devices"]

                port_info["devices"].append(device_info)

            hub_info["ports"].append(port_info)
        hub_info["ports"].sort(key=itemgetter("index"))
        return hub_info

    def get_controllers(self):
        controller_paths: set[Path] = set()

        for bus_path in Path("/sys/bus/usb/devices").iterdir():
            # Only look at buses
            if not bus_path.stem.startswith("usb"):
                continue

            # The parent of the bus is the controller
            controller_paths.add(bus_path.resolve().parent)

        controllers = []

        for controller_path in sorted(controller_paths):
            print(f"Processing controller {controller_path}")

            lspci_output = subprocess.run(["lspci", "-vvvmm", "-s", controller_path.stem], stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE).stdout.decode()
            lspci_output = {i.partition(":\t")[0]: i.partition("\t")[2] for i in lspci_output.splitlines() if i}

            controller = {
                "name": lspci_output["Device"],
                "identifiers": {
                    "bdf": [int(i, 16) for i in
                            [controller_path.name[5:7], controller_path.name[8:10], controller_path.suffix[1]]],
                    "pci_id": [quick_read_2(controller_path, "vendor")[2:],
                               quick_read_2(controller_path, "device")[2:]],
                },
                "ports": [],
            }

            if (controller_revision := (controller_path / "revision")).exists():
                controller["identifiers"]["pci_revision"] = int(quick_read(controller_revision), 16)

            if (sub_pci_vid := (controller_path / "subsystem_vendor")).exists() \
                    and (sub_pci_pid := (controller_path / "subsystem_device")).exists():
                controller["identifiers"]["pci_id"] += [quick_read(sub_pci_vid)[2:],
                                                        quick_read(sub_pci_pid)[2:]]

            if (acpi_path := (controller_path / "firmware_node/path")).exists():
                controller["identifiers"]["acpi_path"] = quick_read(acpi_path)

            controller["class"] = shared.USBControllerTypes(int(quick_read_2(controller_path, "class"), 16) & 0xFF)

            # Enumerate the buses
            for hub in sorted(controller_path.glob("usb*")):
                # maxchild, speed, version
                hubdata = self.enumerate_hub(hub)
                controller["ports"] += hubdata["ports"]
                controller["hub_name"] = hubdata["hub_name"]
                # controller |= hubdata

            controllers.append(controller)

        self.controllers = controllers
        if not self.controllers_historical:
            self.controllers_historical = copy.deepcopy(self.controllers)
        else:
            self.merge_controllers(self.controllers_historical, self.controllers)

    def update_devices(self):
        self.get_controllers()

    def get_companion_port(self, port):
        if not (companion_info := port.get("companion_info")):
            return None
        if not companion_info["hub"] or not companion_info["port"]:
            return None
        if hub := [i for i in self.controllers_historical if i.get("hub_name") == companion_info["hub"]]:
            if port := [i for i in hub[0]["ports"] if i["name"] == companion_info["port"]]:
                return port[0]
        return None


if __name__ == "__main__":
    LinuxUSBMap()
