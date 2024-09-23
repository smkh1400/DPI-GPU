#ifndef RULES_GRAPH_CONFIG_H_
#define RULES_GRAPH_CONFIG_H_

#include <yaml-cpp/yaml.h>

// specify config feilds here as X(feildName, feildType) 
#define _CONFIG_FEILDS_                         \
    X(packetsPerThread, int)                    \
    X(intervalMs, int)                          \
    X(isTimerSet, bool)                         \
    X(mode, short)


namespace ConfigFeilds {

    // declaring feilds to access them in other files
    #define X(feild, typ)   extern typ feild;
    _CONFIG_FEILDS_
    #undef X

}; 

class ConfigLoader {
public:
    ConfigLoader();

    ConfigLoader(const std::string& filepath);

    // open the filepath config file
    void loadConfig(const std::string& filepath);
    
    // loads all feilds specified in _CONFIG_FEILDS_
    static void loadAllFeilds(const std::string& filePath);

    // load specified feild
    template<typename T> T getFeild(const std::string& key);

private:
    YAML::Node config;
    std::string filePath;
};

#endif // RULES_GRAPH_CONFIG_H_