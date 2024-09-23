#include "config.h"
#include <iostream>

namespace ConfigFeilds {

#define X(feild, typ)  typ feild;
_CONFIG_FEILDS_
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
T ConfigLoader::getFeild(const std::string& key) {

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

void ConfigLoader::loadAllFeilds(const std::string& filePath) {

    ConfigLoader cl(filePath);

    #define X(feild, typ) ConfigFeilds::feild = cl.getFeild<typ>(#feild);
    _CONFIG_FEILDS_
    #undef X

    // std::cout << "These feilds loaded from '" << filePath << "':\n";

    // #define X(feild, typ) std::cout << "\t" << #feild << ": " << ConfigFeilds::feild << std::endl;
    // _CONFIG_FEILDS_
    // #undef X
}
