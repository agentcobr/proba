#ifndef MYCLIENT_H
#define MYCLIENT_H

#include <QtWidgets/QWidget>
#include <QTcpSocket>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QLabel>
#include <QTabWidget>

class MyClient : public QWidget {
    Q_OBJECT

public:
    MyClient(const QString& host, int port, QWidget* pwgt = nullptr);

private:
    QTabWidget* m_tabWidget;

    QTcpSocket* m_pTcpSocket;
    QLineEdit* m_ptxtNickname;
    QLineEdit* m_ptxtPassword;
    QLineEdit* m_ptxtPasswordRepeat;
    QLineEdit* m_ptxtEmail;
    QLineEdit* m_ptxtFirstname;
    QLineEdit* m_ptxtLastname;
    QLineEdit* m_ptxtOTP;

    QLineEdit* m_ptxtAuthNickname;
    QLineEdit* m_ptxtAuthPassword;
    QLineEdit* m_ptxtAuthOTP;
    QPushButton* btnStartChat;
    bool isAuthenticated;

    QTextEdit* m_ptxtLog;
    QLabel* photoLabel;
    QPushButton* m_btnClearLog;

    quint16 m_nNextBlockSize; //3

    QWidget* createAccountTab();
    QWidget* authTab();
    QWidget* showLogTab();

    void sendRequest(const QString& action, const QStringList& params);

    bool validatePassword(const QString& password, const QString& passwordRepeat);

    void logEvent(const QString& message, const QString& level);
    QTextEdit* ptxtLog;

private slots:
    void slotReadyRead();
    void slotError(QAbstractSocket::SocketError);
    void clearLog();
};

#endif // MYCLIENT_H
