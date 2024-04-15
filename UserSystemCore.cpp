#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <memory>
#include <algorithm>
#include <chrono>
#include <iomanip>

#pragma region ObjectTypes

struct UserSection {
private:
    std::string sectionName;
    std::map<std::string, std::string> settings;

    friend class UserSectionManager;

public:
    explicit UserSection(std::string name) : sectionName(std::move(name)) {}
};

struct User {
private:
    std::string username;
    std::string password;
    std::map<std::string, std::string> attributes; // email, phone и т.д.
    std::vector<std::shared_ptr<UserSection>> sections;

    friend class UserManager;

public:
    User(std::string username, std::string password)
        : username(std::move(username)), password(std::move(password)) {}
};

#pragma endregion

#pragma region ControllersForObjects

class UserSectionManager {
public:
    static void setSetting(const std::shared_ptr<UserSection>& userSection, const std::string& key, const std::string& value) {
        userSection->settings[key] = value;
    }

    static std::string getSetting(const std::shared_ptr<UserSection>& userSection, const std::string& key)
    {
        const auto it = userSection->settings.find(key);
        if (it != userSection->settings.end()) {
            return it->second;
        }
        return "";
    }

    static void displaySettings(const std::shared_ptr<UserSection>& userSection)
    {
        std::cout << "Settings for " << userSection->sectionName << ":" << std::endl;
        for (const auto& setting : userSection->settings) {
            std::cout << setting.first << " = " << setting.second << std::endl;
        }
    }

    static const std::string& getSectionName(const std::shared_ptr<UserSection>& userSection)
    {
        return userSection->sectionName;
    }

    static const std::map<std::string, std::string>& getSettings(const std::shared_ptr<UserSection>& userSection)
    {
        return userSection->settings;
    }
};

class UserManager {
public:
    static const std::string& getUsername(const std::shared_ptr<User>& user)
    {
        return user->username;
    }

    static bool verifyPassword(const std::shared_ptr<User>& user, const std::string& passwordToVerify)
    {
        return user->password == passwordToVerify; // TODO: !!!!!!! Здесь должно быть сравнение хэшей паролей !!!!!!!
    }

    static void changePassword(const std::shared_ptr<User>& user, const std::string& NewPassword)
    {
        user->password = NewPassword;
    }

    static void setAttribute(const std::shared_ptr<User>& user, const std::string& key, const std::string& value) {
        user->attributes[key] = value;
    }

    static std::vector<std::shared_ptr<UserSection>>& getSections(const std::shared_ptr<User>& user)
    {
        return user->sections;
    }

    static std::string getAttribute(const std::shared_ptr<User>& user, const std::string& key)
    {
        const auto it = user->attributes.find(key);
        if (it != user->attributes.end()) {
            return it->second;
        }
        return "";
    }

    static void addSection(const std::shared_ptr<User>& user, const std::shared_ptr<UserSection>& section) {
        user->sections.push_back(section);
    }

    static void displaySections(const std::shared_ptr<User>& user)
    {
        for (const auto& section : user->sections) {
            UserSectionManager::displaySettings(section);
        }
    }

    static const std::map<std::string, std::string>& getAttributes(const std::shared_ptr<User>& user)
    {
        return user->attributes;
    }
};

class SessionManager {
private:
    std::map<std::string, std::shared_ptr<User>> activeSessions; // Ключ - уникальный ID сессии

public:
    static int getNextSessionNum() {
        static int id = 0;
        return id++;
    }

    std::string startSession(const std::shared_ptr<User>& user) {
        auto sessionId = std::to_string(std::hash<std::string>{}(UserManager::getUsername(user) + std::to_string(getNextSessionNum())));
        activeSessions[sessionId] = user;
        return sessionId;
    }

    std::shared_ptr<User> getUserFromSession(const std::string& sessionId) {
        const auto it = activeSessions.find(sessionId);
        if (it != activeSessions.end()) {
            return it->second;
        }
        return nullptr;
    }

    void endSession(const std::string& sessionId) {
        activeSessions.erase(sessionId);
    }
};

class MetricsManager {
private:
    using MetricTimestamp = std::pair<int, std::chrono::system_clock::time_point>;
    std::map<std::string, std::vector<MetricTimestamp>> metrics;

public:
    void incrementMetric(const std::string& metricName) {
        auto& metric = metrics[metricName];
        if (!metric.empty()) {
            metric.push_back({metric.back().first + 1, std::chrono::system_clock::now()});
        } else {
            metric.push_back({1, std::chrono::system_clock::now()});
        }
    }

    int getMetric(const std::string& metricName) const {
        const auto it = metrics.find(metricName);
        if (it != metrics.end() && !it->second.empty()) {
            return it->second.back().first;
        }
        return 0;
    }

    void reportMetrics() const {
        for (const auto& metric : metrics) {
            std::cout << metric.first << ":\n";
            for (const auto& entry : metric.second) {
                std::time_t time = std::chrono::system_clock::to_time_t(entry.second);
                std::tm timeStruct {};
                
                if (localtime_s(&timeStruct, &time) != 0) {
                    std::cerr << "Failed to convert time properly.\n";
                    continue;  // если time конвертация прошла неудачно
                }
                
                std::cout << "\t" << std::put_time(&timeStruct, "%Y-%m-%d %H:%M:%S") << " - " << entry.first << "\n";
            }
        }
    }
};

#pragma endregion

class UserDataExport {
public:
    static std::string exportUserData(const std::shared_ptr<User>& user) {
        std::string data = "Username: " + UserManager::getUsername(user) + "\n";
        data += "Attributes:\n";
        for (const auto& attr : UserManager::getAttributes(user)) {
            data += attr.first + ": " + attr.second + "\n";
        }

        for (const auto& section : UserManager::getSections(user)) {
            data += "Section: " + UserSectionManager::getSectionName(section) + "\n";
            for (const auto& setting : UserSectionManager::getSettings(section)) {
                data += setting.first + " = " + setting.second + "\n";
            }
        }

        return data;
    }
};

class UserSystemCore {
private:
    SessionManager sessionManager;
    MetricsManager metricsManager;

public:
#pragma region Session
    std::string loginUser(const std::string& username, const std::string& password) {
        const auto user = std::make_shared<User>(username, password); // TODO: !!!!!!!!! Должны получать данные из БД !!!!!!!
        auto sessionId = sessionManager.startSession(user);
        metricsManager.incrementMetric("login_attempts");
        if (UserManager::verifyPassword(user, password)) {
            metricsManager.incrementMetric("successful_logins");
            return sessionId;
        }
        else {
            metricsManager.incrementMetric("failed_logins");
            return "";
        }
    }

    void logoutUser(const std::string& sessionId) {
        sessionManager.endSession(sessionId);
        metricsManager.incrementMetric("logouts");
    }

    bool changeUserPassword(const std::string& sessionId, const std::string& oldPassword, const std::string& newPassword) {
        const auto user = sessionManager.getUserFromSession(sessionId);
        if (user && UserManager::verifyPassword(user, oldPassword)) {
            UserManager::changePassword(user, newPassword);
            metricsManager.incrementMetric("password_changes");
            return true;
        }
        return false;
    }

    void addUserAttribute(const std::string& sessionId, const std::string& key, const std::string& value) {
        const auto user = sessionManager.getUserFromSession(sessionId);
        if (user) {
            UserManager::setAttribute(user, key, value);
            metricsManager.incrementMetric("attribute_changes");
        }
    }

    std::string getUserAttribute(const std::string& sessionId, const std::string& key) {
        const auto user = sessionManager.getUserFromSession(sessionId);
        return user ? UserManager::getAttribute(user, key) : "";
    }

    void addUserSection(const std::string& sessionId, const  std::shared_ptr<UserSection>& section) {
        const auto user = sessionManager.getUserFromSession(sessionId);
        if (user) {
            UserManager::addSection(user, section);
            metricsManager.incrementMetric("section_additions");
        }
    }

    void displayUserSections(const std::string& sessionId) {
        const auto user = sessionManager.getUserFromSession(sessionId);
        if (user) {
            UserManager::displaySections(user);
        }
    }

    std::string exportUserData(const std::string& sessionId) {
        const auto user = sessionManager.getUserFromSession(sessionId);
        return UserDataExport::exportUserData(user);
    }
#pragma endregion

#pragma region Metrics
    void displayMetrics() const
    {
        metricsManager.reportMetrics();
    }

    int getMetric(const std::string& metricName) const
    {
        return metricsManager.getMetric(metricName);
    }

    void resetUserAttributes(const std::string& sessionId) {
        const auto user = sessionManager.getUserFromSession(sessionId);
        if (user) {
            for (auto& attr : UserManager::getAttributes(user)) {
                UserManager::setAttribute(user, attr.first, "");
            }
            metricsManager.incrementMetric("attribute_resets");
        }
    }

    void removeUserSection(const std::string& sessionId, const std::string& sectionName) {
        const auto user = sessionManager.getUserFromSession(sessionId);
        if (user) {
            auto& sections = UserManager::getSections(user);

            for (auto section = sections.begin(); section != sections.end(); ++section) {
                if (UserSectionManager::getSectionName(*section) == sectionName) {
                    sections.erase(section);
                    break;
                }
            }

            metricsManager.incrementMetric("section_removals");
        }
    }

    void updateUserSetting(const std::string& sessionId, const std::string& sectionName, const std::string& key, const std::string& value) {
        const auto user = sessionManager.getUserFromSession(sessionId);
        if (user) {
            const auto& sections = UserManager::getSections(user);

            for (auto& section : sections) {
                if (UserSectionManager::getSectionName(section) == sectionName) {
                    UserSectionManager::setSetting(section, key, value);
                    metricsManager.incrementMetric("setting_updates");
                    break;
                }
            }
        }
    }

    void displayUserSettings(const std::string& sessionId, const std::string& sectionName) {
        const auto user = sessionManager.getUserFromSession(sessionId);
        if (user) {
            const auto& sections = UserManager::getSections(user);
            for (const auto& section : sections) {
                if (UserSectionManager::getSectionName(section) == sectionName) {
                    UserSectionManager::displaySettings(section);
                    break;
                }
            }
        }
    }

#pragma endregion
};



int main() {
    UserSystemCore userSystem;

    // ------------ Регистрация и вход пользователя
    const std::string sessionId = userSystem.loginUser("alex_ukolov", "qwerty");
    if (!sessionId.empty()) {
        std::cout << "User logged in successfully. Session ID: " << sessionId << std::endl;
    }
    else {
        std::cout << "Login failed." << std::endl;
        return 1; // Завершаем программу, если вход не удался
    }

    // ------------ Изменение пароля
    const bool passwordChanged = userSystem.changeUserPassword(sessionId, "qwerty", "qwerty123");
    if (passwordChanged) {
        std::cout << "Password changed successfully." << std::endl;
    }
    else {
        std::cout << "Password change failed." << std::endl;
    }

    // ------------ Добавление атрибутов пользователя
    userSystem.addUserAttribute(sessionId, "email", "alex_ukolov@gmail.com");
    userSystem.addUserAttribute(sessionId, "phone", "1234567890");

    // ------------ Создание пользовательских разделов
    const auto preferences = std::make_shared<UserSection>("preferences");
    UserSectionManager::setSetting(preferences, "theme", "dark");
    userSystem.addUserSection(sessionId, preferences);

    const auto privacy = std::make_shared<UserSection>("privacy");
    UserSectionManager::setSetting(privacy, "data_sharing", "enabled");
    userSystem.addUserSection(sessionId, privacy);

    // ------------ Вывод разделов и их настроек
    std::cout << "User sections and settings:" << std::endl;
    userSystem.displayUserSections(sessionId);

    // ------------ Обновление настройки в разделе
    userSystem.updateUserSetting(sessionId, "preferences", "theme", "light");
    std::cout << "Updated user settings for 'preferences':" << std::endl;
    userSystem.displayUserSettings(sessionId, "preferences");

    // ------------ Инициализация выгрузки данных
    const std::string userData = userSystem.exportUserData(sessionId);
    std::cout << "Exported User Data:" << std::endl;
    std::cout << userData << std::endl;

    // ------------ Вывод метрик
    std::cout << "Metrics Report:" << std::endl;
    userSystem.displayMetrics();

    // ------------ Завершение сессии
    userSystem.logoutUser(sessionId);
    std::cout << "User logged out." << std::endl;

    return 0;
}
