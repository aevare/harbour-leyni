#include <memory>

#include <QGuiApplication>
#include <QLocale>
#include <QQmlContext>
#include <QQuickView>
#include <QTranslator>

#include <sailfishapp.h>

#include "ui/appcontroller.h"

int main(int argc, char *argv[])
{
    std::unique_ptr<QGuiApplication> app(SailfishApp::application(argc, argv));
    app->setOrganizationName(QStringLiteral("harbour-leyni"));
    app->setApplicationName(QStringLiteral("harbour-leyni"));

    // UI translations ship as translations/harbour-leyni-<locale>.qm; try the
    // full system locale (e.g. nb_NO), then the language-only code (nb).
    // With no match the English source strings are used as-is.
    QTranslator *translator = new QTranslator(app.get());
    const QString translationsDir =
        SailfishApp::pathTo(QStringLiteral("translations")).toString();
    const QString locale = QLocale::system().name();
    if (translator->load(QStringLiteral("harbour-leyni-") + locale, translationsDir)
        || translator->load(
               QStringLiteral("harbour-leyni-") + locale.section('_', 0, 0),
               translationsDir)) {
        app->installTranslator(translator);
    }

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
