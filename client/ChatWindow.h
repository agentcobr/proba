#ifndef CHATWINDOW_H
#define CHATWINDOW_H

#include <QWidget>
#include <QTcpSocket>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

class ChatWindow : public QWidget {
    Q_OBJECT

public:
    ChatWindow(QTcpSocket* socket, const QString& nickname, QWidget* parent = nullptr);

private slots:
    void sendMessage();
    void readServerData();
    void handleError(QAbstractSocket::SocketError error);

private:
    QTcpSocket* m_pTcpSocket;
    QString m_nickname;

    QTextEdit* m_ptxtChat;
    QLineEdit* m_ptxtInput;
    QPushButton* m_btnSend;

    void setupUI();
    void sendToServer(const QString& message);
};

#endif // CHATWINDOW_H
