# Linux Shield — métapaquet RPM « linux-shield » : dépend du paquet technique clamav-antivirus (inchangé pour les
# installations existantes) et fournit la commande linux-shield. Construit par build-meta.sh.
Name:           linux-shield
Version:        %{version}
Release:        1%{?dist}
Summary:        Linux Shield — sécurité du poste Linux (métapaquet : installe clamav-antivirus)
License:        Proprietary
URL:            https://github.com/kahsky/linux-shield
BuildArch:      noarch
Requires:       clamav-antivirus

%description
Linux Shield réunit en une application les protections d'un poste Linux : antivirus ClamAV avec service système et
protection en temps réel, pare-feu, centre de sécurité (failles, intégrité, persistance, pot de miel), contrôle des
liens et des courriels, sauvegardes et durcissement. Ce métapaquet installe le paquet technique clamav-antivirus et la
commande linux-shield.

%prep
%build
%install
mkdir -p %{buildroot}%{_bindir}
ln -s /opt/clamav-antivirus/clamav-antivirus.py %{buildroot}%{_bindir}/linux-shield

%files
%{_bindir}/linux-shield
