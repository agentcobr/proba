#include "ChatWindow.h"
#include <QDataStream>
#include <QMessageBox>
#include <QTime>

ChatWindow::ChatWindow(QTcpSocket* socket, const QString& nickname, QWidget* parent)
    : QWidget(parent), m_pTcpSocket(socket), m_nickname(nickname)
{
    setupUI();
    qDebug() << "ChatWindow created with socket state:" << m_pTcpSocket->state();

    if (m_pTcpSocket->state() != QAbstractSocket::ConnectedState) {
        QMessageBox::critical(this, "Error", "Socket is not connected!");
    }
    // Подключение сигналов сокета
    connect(m_pTcpSocket, &QTcpSocket::readyRead, this, &ChatWindow::readServerData);
    connect(m_pTcpSocket, &QTcpSocket::errorOccurred, this, &ChatWindow::handleError);
}

void ChatWindow::setupUI() {
    QVBoxLayout* layout = new QVBoxLayout(this);

    m_ptxtChat = new QTextEdit(this);
    m_ptxtChat->setReadOnly(true);

    m_ptxtInput = new QLineEdit(this);
    m_ptxtInput->setPlaceholderText("Type your message...");

    m_btnSend = new QPushButton("Send", this);
    connect(m_btnSend, &QPushButton::clicked, this, &ChatWindow::sendMessage);
    connect(m_ptxtInput, &QLineEdit::returnPressed, this, &ChatWindow::sendMessage);

    layout->addWidget(m_ptxtChat);
    layout->addWidget(m_ptxtInput);
    layout->addWidget(m_btnSend);

    setWindowTitle("Chat - " + m_nickname);
    resize(600, 400);
}

void ChatWindow::sendMessage() {
    QString message = m_ptxtInput->text().trimmed();
    if (!message.isEmpty()) {
        sendToServer(QString("MSG:%1:%2").arg(m_nickname).arg(message));
        m_ptxtInput->clear();
    }
}

void ChatWindow::sendToServer(const QString& message) {
    QByteArray arrBlock;
    QDataStream out(&arrBlock, QIODevice::WriteOnly);
    out.setVersion(QDataStream::Qt_6_5);

    out << quint16(0) << QTime::currentTime() << message;
    out.device()->seek(0);
    out << quint16(arrBlock.size() - sizeof(quint16));

    m_pTcpSocket->write(arrBlock);
}

void ChatWindow::readServerData() {
    QDataStream in(m_pTcpSocket);
    in.setVersion(QDataStream::Qt_6_5);

    while (true) {
        if (m_pTcpSocket->bytesAvailable() < static_cast<qint64>(sizeof(quint16)))
            break;

        quint16 blockSize;
        in >> blockSize;

        if (m_pTcpSocket->bytesAvailable() < blockSize)
            break;

        QTime time;
        QString message;
        in >> time >> message;

        if (message.startsWith("MSG:")) {
            QStringList parts = message.split(":");
            if (parts.size() >= 3) {
                QString user = parts[1];
                QString msgText = parts.mid(2).join(":");
                m_ptxtChat->append(QString("[%1] %2: %3").arg(time.toString("hh:mm:ss")).arg(user).arg(msgText));
            }
        }
    }
}

void ChatWindow::handleError(QAbstractSocket::SocketError error) {
    Q_UNUSED(error);
    QMessageBox::critical(this, "Error", m_pTcpSocket->errorString());
}
