#ifndef MYSERVER_H
#define MYSERVER_H

#include <QtWidgets/QWidget>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTextEdit>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSslSocket>
#include <QCryptographicHash>
#include <QRandomGenerator>
#include <QMap>
#include <QDateTime>
#include <QVBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QSqlError>
#include <QDebug>
#include <QFile>
#include <QTextStream>
#include <QTimer>
#include <QPushButton>
#include <QList>

class MyServer : public QWidget {
    Q_OBJECT

public:
    explicit MyServer(int port, QWidget* pwgt = nullptr);

private:
    QTcpServer* ptcpServer;
    QTextEdit* ptxtLog;
    QSslSocket* socket;
    QTcpSocket* currentClientSocket;

    QList<QTcpSocket*> clientSockets; // Добавить
    int serverPort;                   // Добавить
    QVBoxLayout* layout;              // Добавить

    QSqlDatabase db;

    QString smtpServer;
    int smtpPort;
    QString emailFrom;
    QString emailPassword;
    quint16 nNextBlockSize;
    QString emailTo;
    QString emailSubject;
    QString emailBody;
    int step;

    QMap<QString, QPair<QString, QDateTime>> optMap;
    QMap<QString, int> attemptCounter;

    void sendToClient(QTcpSocket* pSocket, const QString& str);
    bool addUserToDatabase(const QString& nickname, const QString& firstname, const QString& lastname, const QString& email, const QString& passwordHash);
    bool checkCredentials(const QString& nickname, const QString& password, QString& outEmail);
    QString getClientIp(QTcpSocket* socket);
    QString hashPassword(const QString& password, const QString& salt);

    QString generateOTP();
    void cleanupExpiredOTP();

    void sendEmail(QTcpSocket* clientSocket, const QString& toEmail, const QString& subject, const QString& body);

    void logEvent(const QString& message, const QString& level);

    QPushButton* serverButton;
    bool isServerRunning;

private slots:
    void onConnected();
    void onEncrypted();
    void onReadyRead();
    void slotNewConnection();
    void slotReadClient();
    void toggleServer(); // Добавляем слот для переключения состояния сервера

};

#endif //MYSERVER_H
