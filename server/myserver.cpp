#include "MyServer.h"

#include <QPushButton>
#include <QVBoxLayout>

MyServer::MyServer(int port, QWidget* pwgt)
    : QWidget(pwgt), serverPort(port), layout(new QVBoxLayout(this)), nNextBlockSize(0), step(0), isServerRunning(false) {
    ptcpServer = new QTcpServer(this);
    socket = new QSslSocket(this);

    smtpServer = "smtp.gmail.com";
    smtpPort = 465;
    emailFrom = "ndil.server@gmail.com";
    emailPassword = "erib hnqc uigx iagm";

    serverButton = new QPushButton("Start Server", this);
    connect(serverButton, &QPushButton::clicked, this, &MyServer::toggleServer);

    ptxtLog = new QTextEdit(this);
    ptxtLog->setReadOnly(true);

    layout->addWidget(new QLabel("<h1>Server Ndil Logs</h1>", this));
    layout->addWidget(ptxtLog);
    layout->addWidget(serverButton);

    if (ptcpServer->listen(QHostAddress::Any, serverPort)) {
        isServerRunning = true;
        serverButton->setText("Stop Server");
        logEvent("Server started on port " + QString::number(serverPort), "INFO");
    } else {
        QMessageBox::critical(this, "Server Error",
                              "Unable to start the server: " + ptcpServer->errorString());
        ptcpServer->close();
    }

    connect(ptcpServer, &QTcpServer::newConnection, this, &MyServer::slotNewConnection);

    connect(socket, &QSslSocket::connected, this, &MyServer::onConnected);
    connect(socket, &QSslSocket::encrypted, this, &MyServer::onEncrypted);
    connect(socket, &QSslSocket::readyRead, this, &MyServer::onReadyRead);

    db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName("addressbook.db");

    if (!db.open()) {
        logEvent("Cannot open database: " + db.lastError().text(), "ERROR");
        return;
    }

    QSqlQuery query;
    if (!query.exec("CREATE TABLE IF NOT EXISTS users ("
                    "nickname TEXT PRIMARY KEY, "
                    "firstname TEXT, "
                    "lastname TEXT, "
                    "email TEXT, "
                    "passwordHash TEXT)"))
    {
        logEvent("Table creation error: " + query.lastError().text(), "ERROR");
    }
}

QMap<QString, QPair<QString, QDateTime>> optMap; // OTP и время создания
QMap<QString, int> otpAttemptCounter;           // Счетчик попыток OTP
const int otpLifetimeSeconds = 300;             // Время жизни OTP (5 минут)
const int maxOtpAttempts = 5;                   // Максимальное количество попыток

void MyServer::cleanupExpiredOTP() {
    auto it = optMap.begin();
    while (it != optMap.end()) {
        if (it.value().second.addSecs(otpLifetimeSeconds) < QDateTime::currentDateTime()) {
            logEvent("OTP expired for user: " + it.key(), "INFO");
            it = optMap.erase(it);
        } else {
            ++it;
        }
    }
}

void MyServer::sendToClient(QTcpSocket* pSocket, const QString& str) {
    QByteArray arrBlock;
    QDataStream out(&arrBlock, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_6_5);
    out << quint16(0) << QTime::currentTime() << str;
    out.device()->seek(0);
    out << quint16(arrBlock.size() - sizeof(quint16));

    pSocket->write(arrBlock);
    logEvent("Response sent: " + str, "INFO");
}

bool MyServer::addUserToDatabase(const QString& nickname, const QString& firstname, const QString& lastname, const QString& email, const QString& passwordHash) {
    if (nickname.isEmpty() || firstname.isEmpty() || lastname.isEmpty() || email.isEmpty() || passwordHash.isEmpty()) {
        qDebug() << "One or more fields are empty!";
        logEvent("Failed to insert record: one or more fields are empty.", "ERROR");
        return false;
    }

    QSqlQuery query;
    query.prepare("INSERT INTO users (nickname, firstname, lastname, email, passwordHash) VALUES (?, ?, ?, ?, ?)");
    query.addBindValue(nickname);
    query.addBindValue(firstname);
    query.addBindValue(lastname);
    query.addBindValue(email);
    query.addBindValue(passwordHash);


    //time-to-time------
    qDebug() << "Adding user to database:"
             << "Nickname:" << nickname
             << "Firstname:" << firstname
             << "Lastname:" << lastname
             << "Email:" << email
             << "PasswordHash:" << passwordHash;
    //----------

    if (!query.exec()) {
        logEvent("Failed to insert record: " + query.lastError().text(), "ERROR");
        return false;
    }
    logEvent("Record inserted into database for user: " + nickname, "INFO");
    return true;
}

QString MyServer::getClientIp(QTcpSocket* socket) {
    return socket->peerAddress().toString();
}

void MyServer::slotNewConnection() {
    QTcpSocket* pClientSocket = ptcpServer->nextPendingConnection();
    clientSockets.append(pClientSocket); // Добавляем сокет в список клиентов
    logEvent("New connection from: " + pClientSocket->peerAddress().toString(), "INFO");

    connect(pClientSocket, &QTcpSocket::readyRead, this, &MyServer::slotReadClient);
    connect(pClientSocket, &QTcpSocket::disconnected, [this, pClientSocket]() {
        clientSockets.removeOne(pClientSocket);
        pClientSocket->deleteLater();
        logEvent("Client disconnected: " + pClientSocket->peerAddress().toString(), "INFO");
    });
}

QString MyServer::generateOTP() {
    int randomValue = QRandomGenerator::global()->bounded(100000, 999999);
    return QString::number(randomValue);
}

bool MyServer::checkCredentials(const QString& nickname, const QString& password, QString& outEmail) {
    QSqlQuery query;
    query.prepare("SELECT email, passwordHash FROM users WHERE nickname = ?");
    query.addBindValue(nickname);

    if (query.exec() && query.next()) {
        QString storedPasswordHash = query.value(1).toString();
        if (storedPasswordHash == hashPassword(password, "")) {
            outEmail = query.value(0).toString();
            return true;
        }
    }

    return false;
}

void MyServer::slotReadClient() {
    QTcpSocket* pClientSocket = qobject_cast<QTcpSocket*>(sender());
    if (!pClientSocket || !pClientSocket->isOpen()) return;

    QDataStream in(pClientSocket);
    in.setVersion(QDataStream::Qt_6_5);

    while (pClientSocket->bytesAvailable() > 0) {
        if (nNextBlockSize == 0) {
            if (pClientSocket->bytesAvailable() < static_cast<qint64>(sizeof(quint16))) break;
            in >> nNextBlockSize;
        }

        if (pClientSocket->bytesAvailable() < nNextBlockSize) break;

        QString requestType;
        in >> requestType;

        if (requestType == "REGISTER") {
            QString nickname, firstname, lastname, email, password;
            in >> nickname >> firstname >> lastname >> email >> password;

            QString passwordHash = hashPassword(password, "");
            if (addUserToDatabase(nickname, firstname, lastname, email, passwordHash)) {
                sendToClient(pClientSocket, "REGISTER_SUCCESS");
                logEvent("New user registered: " + nickname, "INFO");
            } else {
                sendToClient(pClientSocket, "REGISTER_FAILED");
                logEvent("Registration failed for user: " + nickname, "ERROR");
            }
        } else if (requestType == "AUTH") {
            QString nickname, password;
            in >> nickname >> password;

            QString userEmail;
            if (checkCredentials(nickname, password, userEmail)) {
                QString otp = generateOTP();
                optMap[nickname] = qMakePair(otp, QDateTime::currentDateTime());

                sendEmail(pClientSocket, userEmail, "2FA for ndil", "Your OTP is: " + otp);
                sendToClient(pClientSocket, "OTP_SENT");
                logEvent("OTP sent to user: " + nickname, "INFO");
            } else {
                sendToClient(pClientSocket, "AUTH_FAILED");
                logEvent("Authentication failed for user: " + nickname, "WARNING");
            }
        } else if (requestType == "VERIFY_OTP") {
            QString nickname, otp;
            in >> nickname >> otp;

            cleanupExpiredOTP();

            if (optMap.contains(nickname)) {
                auto otpData = optMap[nickname];
                if (otpData.second.addSecs(otpLifetimeSeconds) < QDateTime::currentDateTime()) {
                    optMap.remove(nickname);
                    sendToClient(pClientSocket, "OTP_EXPIRED");
                    logEvent("OTP expired for user: " + nickname, "INFO");
                } else if (otpData.first == otp) {
                    optMap.remove(nickname);
                    otpAttemptCounter.remove(nickname);
                    sendToClient(pClientSocket, "AUTH_SUCCESS");
                    logEvent("Authentication successful for user: " + nickname, "INFO");
                }
                else {
                    otpAttemptCounter[nickname]++;
                    if (otpAttemptCounter[nickname] > maxOtpAttempts) {
                        logEvent("Account temporarily blocked: " + nickname, "WARNING");
                        sendToClient(pClientSocket, "ACCOUNT_BLOCKED");
                    } else {
                        sendToClient(pClientSocket, "OTP_INVALID");
                        logEvent("Invalid OTP attempt for user: " + nickname, "WARNING");
                    }
                }
            } else {
                sendToClient(pClientSocket, "AUTH_FAILED");
                logEvent("Authentication failed: OTP not found for user: " + nickname, "WARNING");
            }
        } else if (requestType == "MSG") {
            QString fullMessage;
            in >> fullMessage;

            QStringList parts = fullMessage.split(":");
            if (parts.size() >= 3 && parts[0] == "MSG") {
                QString user = parts[1];
                QString message = parts.mid(2).join(":");

                logEvent("Received message from " + user + ": " + message, "INFO");

                // Отправка всем клиентам
                for (QTcpSocket* client : clientSockets) {
                    if (client->state() == QTcpSocket::ConnectedState) {
                        QByteArray data;
                        QDataStream out(&data, QIODevice::WriteOnly);
                        out.setVersion(QDataStream::Qt_6_5);
                        out << quint16(0) << QTime::currentTime() << QString("MSG:%1:%2").arg(user).arg(message);
                        out.device()->seek(0);
                        out << quint16(data.size() - sizeof(quint16));
                        client->write(data);
                    }
                }
            }
        }

        nNextBlockSize = 0;
    }
}

QString MyServer::hashPassword(const QString& password, const QString& salt) {
    QByteArray saltedPassword = (password + salt).toUtf8();
    return QString(QCryptographicHash::hash(saltedPassword, QCryptographicHash::Sha256).toHex());
}


void MyServer::logEvent(const QString& message, const QString& level) {
    QString logMessage = QString("[%1] [%2]: %3")
    .arg(QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss"))
        .arg(level)
        .arg(message);
    qDebug() << logMessage;

    if (ptxtLog) {
        ptxtLog->append(logMessage);
    }
}

void MyServer::toggleServer() {
    if (isServerRunning) {
        ptcpServer->close();
        for (QTcpSocket* client : clientSockets) {
            if (client->state() == QAbstractSocket::ConnectedState) {
                client->disconnectFromHost();
                client->deleteLater();
            }
        }
        clientSockets.clear();
        isServerRunning = false;
        serverButton->setText("Start Server");
        logEvent("Server stopped", "INFO");
    } else {
        if (ptcpServer->listen(QHostAddress::Any, serverPort)) {
            connect(ptcpServer, &QTcpServer::newConnection, this, &MyServer::slotNewConnection);
            isServerRunning = true;
            serverButton->setText("Stop Server");
            logEvent("Server started on port " + QString::number(serverPort), "INFO");
        } else {
            QMessageBox::critical(this, "Server Error",
                                  "Unable to start server: " + ptcpServer->errorString());
        }
    }
}
