#include <memory>

#include <QGuiApplication>
#include <QQmlContext>
#include <QQuickView>

#include <sailfishapp.h>

#include "ui/appcontroller.h"

int main(int argc, char *argv[])
{
    std::unique_ptr<QGuiApplication> app(SailfishApp::application(argc, argv));
    app->setOrganizationName(QStringLiteral("harbour-leyni"));
    app->setApplicationName(QStringLiteral("harbour-leyni"));

    Leyni::Ui::AppController controller;

    std::unique_ptr<QQuickView> view(SailfishApp::createView());
    // The controller is the ONLY bridge between QML and the vault; QML gets
    // no other C++ objects (see doc/ARCHITECTURE.md).
    view->rootContext()->setContextProperty(QStringLiteral("App"),
                                            &controller);
    view->setSource(SailfishApp::pathTo(
        QStringLiteral("qml/harbour-leyni.qml")));
    view->show();

    return app->exec();
}
