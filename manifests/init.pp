class opendj (
  $group                   = hiera('opendj::group', 'opendj'),
  $user                    = hiera('opendj::user', 'opendj'),
  $home                    = hiera('opendj::home', '/opt/opendj'),
  $ldap_port               = hiera('opendj::ldap_port', '1389'),
  $ldaps_port              = hiera('opendj::ldaps_port', '1636'),
  $repl_port               = hiera('opendj::repl_port', '8989'),
  $admin_user              = hiera('opendj::admin_user', 'cn=Directory Manager'),
  $admin_port              = hiera('opendj::admin_port', '4444'),
  $admin_password          = hiera('opendj::admin_password'),
  $host                    = $facts['fqdn'],
  $host_name               = $facts['hostname'],
  $base_dn                 = hiera('opendj::base_dn', 'dc=example,dc=com'),
  $master                  = hiera('opendj::master', undef),
  $java_properties         = hiera('opendj::java_properties', undef),
  $backend_name            = hiera('opendj::backend_name','cfgStore'),
  $backend_type            = hiera('opendj::backend_type','local-db'),
  $password_validator_name = hiera('opendj::password_validator_name','Custom-Character Password Validator'),
  $default_policy_name     = hiera('opendj::default_policy_name','Default Password Policy')
) {
  $common_opts = "-h ${host} --bindDN ${admin_user} --bindPassword ${admin_password}"
  $dsconfig = "${home}/bin/dsconfig ${common_opts} --port ${admin_port}"
  $dsreplication = "${home}/bin/dsreplication --adminUID admin --adminPassword ${admin_password} -X -n"

  package { 'java-1.8.0-openjdk':
    ensure => 'installed'
  }

  package { 'opendj':
    ensure   => 'installed',
  }

  group { $group:
    ensure => 'present',
  }

  user { $user:
    ensure     => 'present',
    groups     => $group,
    comment    => 'OpenDJ LDAP daemon',
    home       => $home,
    managehome => true,
    require    => Group[$group],
  }

  file { $home:
    recurse => true,
    ensure  => directory,
    owner   => $user,
    group   => $group,
    require => [User[$user], Package['opendj']],
  }

  file_line { 'file_limits_soft':
    path    => '/etc/security/limits.conf',
    line    => "${user} soft nofile 65536",
    require => User[$user],
  }

  file_line { 'file_limits_hard':
    path    => '/etc/security/limits.conf',
    line    => "${user} hard nofile 131072",
    require => User[$user],
  }

  exec { 'configure opendj':
    command => "/bin/su opendj -s /bin/bash -c '${home}/setup --cli \
    	--ldapPort ${ldap_port} \
    	--adminConnectorPort ${admin_port} \
    	--rootUserDN ${admin_user} \
    	--rootUserPassword ${admin_password} \
    	--enableStartTLS \
    	--ldapsPort ${ldaps_port} \
    	--generateSelfSignedCertificate \
    	--hostName ${host} \
    	--no-prompt \
    	--noPropertiesFile \
      --acceptLicense --doNotStart '",
    creates => "${home}/config",
    notify  => Exec['create RC script'],
  }

  exec { 'create RC script':
    require => Package['opendj'],
    command => "${home}/bin/create-rc-script --userName ${user} \
        --outputFile /etc/init.d/opendj",
    creates => '/etc/init.d/opendj',
    notify  => Service['opendj'],
  }

  service { 'opendj':
    ensure     => running,
    require    => Exec['create RC script'],
    enable     => true,
    hasrestart => true,
    hasstatus  => false,
    status     => "${home}/bin/status -D \"${admin_user}\" \
        --bindPassword ${admin_password} | grep --quiet Started",
  }

  exec { 'create-backend':
    require => Service['opendj'],
    command => "${dsconfig} create-backend --backend-name ${backend_name} --set base-dn:${base_dn} --set enabled:true --type ${backend_type} --no-prompt",
    unless => "${dsconfig} get-backend-prop --backend-name ${backend_name} | grep ${backend_name}"
  }

  exec { 'create custom password validator':
    require => Service['opendj'],
    command => "${dsconfig} create-password-validator --validator-name \"${password_validator_name}\" \
                --set allow-unclassified-characters:true --set enabled:true --set character-set:1:ABCDEFGHIJKLMNOPQRSTUVWXYZ \
                --set character-set:1:0123456789 --set min-character-sets:2 --type character-set --no-prompt",
    unless => "${dsconfig} list-password-validators | grep \"${password_validator_name}\""
  }

  exec { 'add password validator to a default policy':
    require => Service['opendj'],
    command => "${dsconfig} set-password-policy-prop --policy-name \"${default_policy_name}\" \
                --set password-validator:\"${password_validator_name}\" --no-prompt",
    unless => "${dsconfig} get-password-policy-prop --policy-name \"${default_policy_name}\" | grep \"${password_validator_name}\""
  }

  if (!empty($master) and $host != $master) {
    exec { 'enable replication':
      require => Service['opendj'],
      command => "/bin/su ${user} -s /bin/bash -c \"$dsreplication enable \
        --host1 ${master} --port1 ${admin_port} \
        --replicationPort1 ${repl_port} \
        --bindDN1 '${admin_user}' --bindPassword1 ${admin_password} \
        --host2 ${host} --port2 ${admin_port} \
        --replicationPort2 ${repl_port} \
        --bindDN2 '${admin_user}' --bindPassword2 ${admin_password} \
        --baseDN '${base_dn}'\"",
      unless  => "/bin/su ${user} -s /bin/bash -c \"$dsreplication \
        status | grep ${host} | cut -d : -f 5 | grep true\"",
      notify  => Exec['initialize replication']
    }

    exec { 'initialize replication':
      command     => "/bin/su ${user} -s /bin/bash -c \"$dsreplication initialize \
        -h ${master} -p ${admin_port} -O ${host} --baseDN ${base_dn}\"",
      require     => Exec['enable replication'],
      refreshonly => true,
    }
  }

  if ($java_properties != undef) {
    validate_hash($java_properties)
    create_resources('opendj::java_property', $java_properties)

    exec { 'apply java properties':
      command => "/bin/su ${user} -s /bin/bash -c \"${home}/bin/dsjavaproperties\"",
      notify  => Service['opendj'],
    }
  }

  define opendj::java_property($value) {
    file_line { "java_property:${title}":
      path    => "${home}/config/java.properties",
      line    => "${title}=${value}",
      match   => "^(${title}=).*$",
      require => Exec['configure opendj'],
      notify  => Exec['apply java properties'],
    }
  }

}