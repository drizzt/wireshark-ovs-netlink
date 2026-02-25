Name:           wireshark-ovs-netlink
Version:        0.1.0
Release:        %{?autorelease}%{!?autorelease:1%{?dist}}
Summary:        Open vSwitch Netlink dissector plugin for Wireshark
License:        GPL-2.0-or-later
URL:            https://github.com/drizzt/wireshark-ovs-netlink
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildRequires:  cmake >= 3.16
BuildRequires:  gcc
BuildRequires:  wireshark-devel

%description
An out-of-tree Wireshark dissector plugin that decodes all six Open vSwitch
generic netlink families: ovs_vport, ovs_datapath, ovs_flow, ovs_packet,
ovs_meter, and ovs_ct_limit.

%prep
%autosetup

%build
%cmake
%cmake_build

%install
%cmake_install

%check
%ctest

%files
%license LICENSE
%doc README.md
%{_libdir}/wireshark/plugins/*/epan/ovs_netlink.so

%changelog
%{?autochangelog}
%{!?autochangelog:
* Wed Feb 25 2026 Timothy Redaelli <tredaelli@redhat.com> - 0.1.0-1
- Initial package
}
