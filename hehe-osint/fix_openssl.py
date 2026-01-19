def main():
    with open('/etc/ssl/openssl.cnf', 'r+') as f:
        provider_sect_set = False
        default_sect_set = False
        legacy_sect_set = False

        config = f.read()
        config = config.split('\n')
        for i in range(len(config)):
            if config[i].startswith('[provider_sect]'):
                config[i+1] = "default_sect"
                config[i+2] = "legacy_sect"
                provider_sect_set = True
                print("Set provider_sect")
            if config[i].startswith('[default_sect]'):
                config[i+1] = "activate = 1"
                default_sect_set = True
                print("Set default_sect")
            if config[i].startswith('[legacy_sect]'):
                config[i+1] = "activate = 1"
                legacy_sect_set = True
                print("Set legacy_sect")
        
        if not provider_sect_set:
            config.append('[provider_sect]')
            config.append('default = default_sect')
            config.append('legacy = legacy_sect')
            print("Added provider_sect after")
        if not default_sect_set:
            config.append('[default_sect]')
            config.append('activate = 1')
            print("Added default_sect after")
        if not legacy_sect_set:
            config.append('[legacy_sect]')
            config.append('activate = 1')
            print("Added legacy_sect after")
    
        f.seek(0)
        f.write('\n'.join(config))
        f.truncate()
main()