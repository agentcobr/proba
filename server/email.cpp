#include "MyServer.h"

void MyServer::sendEmail(QTcpSocket* clientSocket, const QString& toEmail, const QString& subject, const QString& body) {
    emailTo = toEmail;
    emailSubject = subject;
    emailBody = body;

    qDebug() << "Sending email:";
    qDebug() << "To:" << toEmail;
    qDebug() << "Subject:" << subject;
    qDebug() << "Body:" << body;

    currentClientSocket = clientSocket; // Сохраняем ссылку на клиентский сокет

    if (!socket) {
        socket = new QSslSocket(this);
        // Переподключаем сигналы
        connect(socket, &QSslSocket::connected, this, &MyServer::onConnected);
        connect(socket, &QSslSocket::encrypted, this, &MyServer::onEncrypted);
        connect(socket, &QSslSocket::readyRead, this, &MyServer::onReadyRead);
    }

    if (clientSocket && clientSocket->isOpen()) {
        clientSocket->write("Email sent successfully.\n");
    }

    socket->connectToHostEncrypted(smtpServer, smtpPort);
}

void MyServer::onConnected() { qDebug() << "Connected to SMTP server"; }

void MyServer::onEncrypted()
{
    qDebug() << "Connection encrypted";

    socket->write("EHLO localhost\r\n");
    step = 1;
}

void MyServer::onReadyRead() {
    QString response = socket->readAll();
    qDebug() << "SMTP Response:" << response;

    if (response.isEmpty()) {
        logEvent("Empty response from SMTP server.", "ERROR");
        sendToClient(currentClientSocket, "EMAIL_FAILED");
        return;
    }

    switch (step) {
    case 1:
        if (response.startsWith("220")) {
            socket->write("EHLO localhost\r\n");
            step = 2;
        } else {
            logEvent("SMTP server not ready: " + response, "ERROR");
            sendToClient(currentClientSocket, "EMAIL_FAILED");
        }
        break;
    case 2:
        if (response.contains("250")) {
            socket->write("AUTH LOGIN\r\n");
            step = 3;
        } else {
            logEvent("EHLO failed: " + response, "ERROR");
            sendToClient(currentClientSocket, "EMAIL_FAILED");
        }
        break;
    case 3:
        if (response.startsWith("334")) {
            QString encodedLogin = QString(emailFrom.toUtf8().toBase64());
            logEvent("Sending login: " + encodedLogin, "DEBUG");
            socket->write(encodedLogin.toUtf8() + "\r\n");
            step = 4;
        }
        //} else {
        //    logEvent("AUTH LOGIN failed: " + response, "ERROR");
        //    sendToClient(currentClientSocket, "EMAIL_FAILED");
        //}
        break;
    case 4: // Отправка пароля
        if (response.startsWith("334")) {
            QString encodedPassword = QString(emailPassword.toUtf8().toBase64());
            logEvent("Sending password: [hidden]", "DEBUG");
            socket->write(encodedPassword.toUtf8() + "\r\n");
            step = 5;
        } else {
            logEvent("Login failed: " + response, "ERROR");
            sendToClient(currentClientSocket, "EMAIL_FAILED");
        }
        break;
    case 5:
        if (response.contains("235")) {
            socket->write(QString("MAIL FROM:<%1>\r\n").arg(emailFrom).toUtf8());
            step = 6;
        } else {
            logEvent("Authentication failed: " + response, "ERROR");
            sendToClient(currentClientSocket, "EMAIL_FAILED");
        }
        break;
    case 6:
        if (response.contains("250")) {
            socket->write(QString("RCPT TO:<%1>\r\n").arg(emailTo).toUtf8());
            step = 7;
        } else {
            logEvent("MAIL FROM failed: " + response, "ERROR");
            sendToClient(currentClientSocket, "EMAIL_FAILED");
        }
        break;
    case 7:
        if (response.contains("250")) {
            socket->write("DATA\r\n");
            step = 8;
        } else {
            logEvent("RCPT TO failed: " + response, "ERROR");
            sendToClient(currentClientSocket, "EMAIL_FAILED");
        }
        break;
    case 8:
        if (response.contains("354")) {
            QString message = QString("Subject: %1\r\n\r\n%2\r\n.\r\n").arg(emailSubject, emailBody);
            socket->write(message.toUtf8());
            step = 9;
        } else {
            logEvent("DATA command failed: " + response, "ERROR");
            sendToClient(currentClientSocket, "EMAIL_FAILED");
        }
        break;
    case 9:
        if (response.contains("250")) {
            socket->write("QUIT\r\n");
            step = 10;
        } else {
            logEvent("Message sending failed: " + response, "ERROR");
            sendToClient(currentClientSocket, "EMAIL_FAILED");
        }
        break;
    case 10:
        if (response.contains("221")) {
            logEvent("Email sent successfully!", "INFO");
            sendToClient(currentClientSocket, "EMAIL_SENT");
            socket->deleteLater(); // Уничтожаем сокет после использования
            socket = nullptr;
        }
        break;
    default:
        logEvent("Unknown SMTP step: " + QString::number(step), "ERROR");
    }
}
