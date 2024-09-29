#include "config.h"
#include <iostream>

namespace Configfields {

#define X(field, typ)  typ field;
    _CONFIG_fieldS_
#undef X

};

ConfigLoader::ConfigLoader() {}

ConfigLoader::ConfigLoader(const std::string& filepath) {
    loadConfig(filepath);
}

void ConfigLoader::loadConfig(const std::string& filepath) {

    try {
        config = YAML::LoadFile(filepath);
        
    } catch (const YAML::BadFile& e) {

        throw std::runtime_error("Error: Failed to open the configuration File '" + filepath + "'.");
    }

    filePath = filepath;
}

template<typename T>
T ConfigLoader::getfield(const std::string& key) {

    try {
        if(!config[key]) {
            throw std::runtime_error("Error: Key '" + key + "' not found in the configuration File '" + filePath + "'.");
        }

        return config[key].as<T>();
    } catch(const YAML::BadConversion& e) {

        throw std::runtime_error("Error: Failed to convert the key '" + key + "' to the requested type: " + std::string(e.what()));
    } catch (const std::exception& e) {

        throw std::runtime_error("Error: Failed To retrieve key '" + key + "': " + std::string(e.what()));
    }
}

void ConfigLoader::loadAllfields(const std::string& filePath) {

    ConfigLoader cl(filePath);

    #define X(field, typ) Configfields::field = cl.getfield<typ>(#field);
        _CONFIG_fieldS_
    #undef X

    std::cout << "These fields loaded from '" << filePath << "':\n";

    #define X(field, typ) std::cout << "\t" << #field << ": " << Configfields::field << std::endl;
        _CONFIG_fieldS_
    #undef X
}
