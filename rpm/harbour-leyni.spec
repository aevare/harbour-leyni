Name:       harbour-leyni

Summary:    Native, open-source Bitwarden client for Sailfish OS
Version:    0.1.2
Release:    1
# GPL-3.0-or-later; tag uses Fedora-style form required by the Sailfish rpmlint allowlist
License:    GPLv3+
URL:        https://github.com/aevare/harbour-leyni
Source0:    %{name}-%{version}.tar.bz2
Requires:   sailfishsilica-qt5 >= 0.10.9
BuildRequires:  pkgconfig(sailfishapp) >= 1.0.2
BuildRequires:  pkgconfig(Qt5Core)
BuildRequires:  pkgconfig(Qt5Qml)
BuildRequires:  pkgconfig(Qt5Quick)
BuildRequires:  pkgconfig(Qt5Network)
BuildRequires:  pkgconfig(Qt5Concurrent)
BuildRequires:  pkgconfig(libcrypto)
BuildRequires:  desktop-file-utils
BuildRequires:  cmake

%description
Native, open-source Bitwarden client for Sailfish OS

%if 0%{?_chum}
Title: Leyni
Type: desktop-application
DeveloperName: Ævar Eggertsson
Categories:
 - Utility
Custom:
  Repo: https://github.com/aevare/harbour-leyni
Links:
  Homepage: https://github.com/aevare/harbour-leyni
  Bugtracker: https://github.com/aevare/harbour-leyni/issues
PackageIcon: https://raw.githubusercontent.com/aevare/harbour-leyni/main/icons/172x172/harbour-leyni.png
%endif


%prep
%setup -q -n %{name}-%{version}

%build
%cmake -DBUILD_APP=ON
%make_build

%install
%make_install

# Strip the main binary here so release RPMs are stripped even when the build
# is driven by tooling that cannot pass `mb2 -d` (e.g. the CI build action).
strip %{buildroot}%{_bindir}/%{name}

desktop-file-install --delete-original \
    --dir %{buildroot}%{_datadir}/applications \
    %{buildroot}%{_datadir}/applications/*.desktop

%files
%defattr(-,root,root,-)
%{_bindir}/%{name}
%{_datadir}/%{name}
%{_datadir}/applications/%{name}.desktop
%{_datadir}/icons/hicolor/*/apps/%{name}.png
