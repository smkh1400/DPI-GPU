#ifndef RULES_GRAPH_CONFIG_H_
#define RULES_GRAPH_CONFIG_H_

#include <yaml-cpp/yaml.h>

// specify config fields here as X(fieldName, fieldType) 
#define _CONFIG_fieldS_                         \
    X(isTimerSet, bool)                         \
    X(readPacketMode, std::string)              \
    X(chunkCountLimit, int)                     \
    X(chunkTimeLimit, double)                    

#define CONFIG_FIELD_INT_NOT_SET_VAL                (-1)  
#define CONFIG_FIELD_DOUBLE_NOT_SET_VAL             (-1.0)  

namespace Configfields {

    // declaring fields to access them in other files
#define X(field, typ)   extern typ field;
    _CONFIG_fieldS_
#undef X

}; 

class ConfigLoader {
public:
    ConfigLoader();

    ConfigLoader(const std::string& filepath);

    // open the filepath config file
    void loadConfig(const std::string& filepath);
    
    // loads all fields specified in _CONFIG_fieldS_
    static void loadAllfields(const std::string& filePath);

    // load specified field
    template<typename T> T getfield(const std::string& key);

private:
    YAML::Node config;
    std::string filePath;
};

#endif // RULES_GRAPH_CONFIG_H_