#ifdef QT_QML_DEBUG
#include <QtQuick>
#endif

#include <sailfishapp.h>

int main(int argc, char *argv[])
{
    // SailfishApp::main() displays "qml/harbour-bitvault.qml" automatically.
    // For more control, use SailfishApp::application(), createView(), pathTo().
    return SailfishApp::main(argc, argv);
}
