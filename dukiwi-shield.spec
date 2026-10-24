# Dukiwi Shield — métapaquet RPM « dukiwi-shield » : dépend du paquet technique clamav-antivirus (inchangé pour les
# installations existantes) et fournit la commande dukiwi-shield. Construit par build-meta.sh.
Name:           dukiwi-shield
Version:        %{version}
Release:        1%{?dist}
Summary:        Dukiwi Shield — antivirus, protection et vérification d'intégrité pour Linux (métapaquet)
License:        Proprietary
URL:            https://github.com/kahsky/dukiwi-shield
BuildArch:      noarch
Requires:       clamav-antivirus

%description
Dukiwi Shield réunit en une application les protections d'un poste Linux : antivirus ClamAV avec service système et
protection en temps réel, pare-feu, centre de sécurité (failles, intégrité, persistance, pot de miel), contrôle des
liens et des courriels, sauvegardes et durcissement. Ce métapaquet installe le paquet technique clamav-antivirus et la
commande dukiwi-shield.

%prep
%build
%install
mkdir -p %{buildroot}%{_bindir}
ln -s /opt/clamav-antivirus/clamav-antivirus.py %{buildroot}%{_bindir}/dukiwi-shield

%files
%{_bindir}/dukiwi-shield
