# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'interface.ui'
#
# Created by: PyQt5 UI code generator 5.15.6
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1200, 900)
        MainWindow.setMinimumSize(QtCore.QSize(1200, 900))
        MainWindow.setMaximumSize(QtCore.QSize(1200, 900))
        MainWindow.setAutoFillBackground(True)
        MainWindow.setStyleSheet("background-image: url(:/bg/img/cd1783ef9fcc4abf075ae1651034c91c.png);\n"
"background-image: url(:/bg/img/cd1783ef9fcc4abf075ae1651034c91c.png);\n"
"background-position: center;\n"
"color: white;\n"
"")
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setAutoFillBackground(True)
        self.centralwidget.setStyleSheet("")
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setSpacing(0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.header = QtWidgets.QFrame(self.centralwidget)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.header.setFont(font)
        self.header.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.header.setFrameShadow(QtWidgets.QFrame.Raised)
        self.header.setLineWidth(1)
        self.header.setObjectName("header")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.header)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout.setSpacing(0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.title = QtWidgets.QFrame(self.header)
        self.title.setFrameShape(QtWidgets.QFrame.WinPanel)
        self.title.setFrameShadow(QtWidgets.QFrame.Raised)
        self.title.setLineWidth(10)
        self.title.setObjectName("title")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.title)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label = QtWidgets.QLabel(self.title)
        font = QtGui.QFont()
        font.setPointSize(20)
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setObjectName("label")
        self.horizontalLayout_2.addWidget(self.label, 0, QtCore.Qt.AlignTop)
        self.horizontalLayout.addWidget(self.title)
        self.verticalLayout.addWidget(self.header)
        self.body = QtWidgets.QFrame(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.body.sizePolicy().hasHeightForWidth())
        self.body.setSizePolicy(sizePolicy)
        self.body.setAutoFillBackground(True)
        self.body.setStyleSheet("")
        self.body.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.body.setFrameShadow(QtWidgets.QFrame.Raised)
        self.body.setObjectName("body")
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout(self.body)
        self.horizontalLayout_5.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_5.setSpacing(0)
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.leftMenu = QtWidgets.QFrame(self.body)
        self.leftMenu.setMinimumSize(QtCore.QSize(0, 650))
        self.leftMenu.setMaximumSize(QtCore.QSize(16777215, 650))
        self.leftMenu.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.leftMenu.setFrameShadow(QtWidgets.QFrame.Raised)
        self.leftMenu.setLineWidth(5)
        self.leftMenu.setObjectName("leftMenu")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.leftMenu)
        self.verticalLayout_3.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_3.setSpacing(0)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.topbar = QtWidgets.QFrame(self.leftMenu)
        self.topbar.setMinimumSize(QtCore.QSize(0, 60))
        self.topbar.setMaximumSize(QtCore.QSize(16777215, 60))
        self.topbar.setStyleSheet("background-color: rgb(185, 215, 234);")
        self.topbar.setFrameShape(QtWidgets.QFrame.WinPanel)
        self.topbar.setFrameShadow(QtWidgets.QFrame.Raised)
        self.topbar.setLineWidth(3)
        self.topbar.setObjectName("topbar")
        self.horizontalLayout_8 = QtWidgets.QHBoxLayout(self.topbar)
        self.horizontalLayout_8.setContentsMargins(10, 0, 30, 0)
        self.horizontalLayout_8.setSpacing(0)
        self.horizontalLayout_8.setObjectName("horizontalLayout_8")
        self.frame_11 = QtWidgets.QFrame(self.topbar)
        self.frame_11.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.frame_11.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_11.setObjectName("frame_11")
        self.horizontalLayout_9 = QtWidgets.QHBoxLayout(self.frame_11)
        self.horizontalLayout_9.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_9.setSpacing(20)
        self.horizontalLayout_9.setObjectName("horizontalLayout_9")
        self.menuButton = QtWidgets.QPushButton(self.frame_11)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.menuButton.setFont(font)
        self.menuButton.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.menuButton.setStyleSheet("background-color: rgb(195, 174, 214);\n"
"")
        self.menuButton.setObjectName("menuButton")
        self.horizontalLayout_9.addWidget(self.menuButton)
        self.billsButton = QtWidgets.QPushButton(self.frame_11)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.billsButton.setFont(font)
        self.billsButton.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.billsButton.setStyleSheet("background-color: rgb(195, 174, 214);")
        self.billsButton.setObjectName("billsButton")
        self.horizontalLayout_9.addWidget(self.billsButton)
        self.horizontalLayout_8.addWidget(self.frame_11, 0, QtCore.Qt.AlignLeft)
        self.frame_12 = QtWidgets.QFrame(self.topbar)
        self.frame_12.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.frame_12.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_12.setObjectName("frame_12")
        self.horizontalLayout_10 = QtWidgets.QHBoxLayout(self.frame_12)
        self.horizontalLayout_10.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_10.setSpacing(20)
        self.horizontalLayout_10.setObjectName("horizontalLayout_10")
        self.pushButton_6 = QtWidgets.QPushButton(self.frame_12)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.pushButton_6.setFont(font)
        self.pushButton_6.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.pushButton_6.setStyleSheet("background-color: rgb(195, 174, 214);")
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(":/newPrefix/icons/feather/search.svg"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.pushButton_6.setIcon(icon)
        self.pushButton_6.setObjectName("pushButton_6")
        self.horizontalLayout_10.addWidget(self.pushButton_6)
        self.pushButton_8 = QtWidgets.QPushButton(self.frame_12)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.pushButton_8.setFont(font)
        self.pushButton_8.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.pushButton_8.setStyleSheet("background-color: rgb(195, 174, 214);")
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(":/newPrefix/icons/cil-settings.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.pushButton_8.setIcon(icon1)
        self.pushButton_8.setObjectName("pushButton_8")
        self.horizontalLayout_10.addWidget(self.pushButton_8)
        self.pushButton_7 = QtWidgets.QPushButton(self.frame_12)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.pushButton_7.setFont(font)
        self.pushButton_7.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.pushButton_7.setStyleSheet("background-color: rgb(195, 174, 214);")
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(":/newPrefix/icons/cil-user.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.pushButton_7.setIcon(icon2)
        self.pushButton_7.setObjectName("pushButton_7")
        self.horizontalLayout_10.addWidget(self.pushButton_7)
        self.horizontalLayout_8.addWidget(self.frame_12, 0, QtCore.Qt.AlignRight)
        self.verticalLayout_3.addWidget(self.topbar, 0, QtCore.Qt.AlignTop)
        self.main_2 = QtWidgets.QFrame(self.leftMenu)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.main_2.sizePolicy().hasHeightForWidth())
        self.main_2.setSizePolicy(sizePolicy)
        self.main_2.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.main_2.setFrameShadow(QtWidgets.QFrame.Raised)
        self.main_2.setObjectName("main_2")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.main_2)
        self.verticalLayout_4.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_4.setSpacing(0)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.stackedWidget = QtWidgets.QStackedWidget(self.main_2)
        self.stackedWidget.setFrameShape(QtWidgets.QFrame.WinPanel)
        self.stackedWidget.setFrameShadow(QtWidgets.QFrame.Raised)
        self.stackedWidget.setLineWidth(3)
        self.stackedWidget.setObjectName("stackedWidget")
        self.menu = QtWidgets.QWidget()
        self.menu.setObjectName("menu")
        self.horizontalLayout_12 = QtWidgets.QHBoxLayout(self.menu)
        self.horizontalLayout_12.setContentsMargins(10, 0, 0, 5)
        self.horizontalLayout_12.setObjectName("horizontalLayout_12")
        self.sideBar = QtWidgets.QFrame(self.menu)
        self.sideBar.setMinimumSize(QtCore.QSize(0, 0))
        self.sideBar.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.sideBar.setStyleSheet("background-color: rgb(185, 215, 234);")
        self.sideBar.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.sideBar.setFrameShadow(QtWidgets.QFrame.Raised)
        self.sideBar.setLineWidth(3)
        self.sideBar.setObjectName("sideBar")
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.sideBar)
        self.verticalLayout_5.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_5.setSpacing(0)
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.frame_14 = QtWidgets.QFrame(self.sideBar)
        self.frame_14.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.frame_14.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_14.setObjectName("frame_14")
        self.verticalLayout_6 = QtWidgets.QVBoxLayout(self.frame_14)
        self.verticalLayout_6.setContentsMargins(0, 9, 0, 0)
        self.verticalLayout_6.setSpacing(20)
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.foods = QtWidgets.QPushButton(self.frame_14)
        self.foods.setMinimumSize(QtCore.QSize(0, 50))
        self.foods.setMaximumSize(QtCore.QSize(16777215, 50))
        self.foods.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.foods.setStyleSheet("background-color: rgb(192, 216, 192);")
        self.foods.setObjectName("foods")
        self.verticalLayout_6.addWidget(self.foods)
        self.drinks = QtWidgets.QPushButton(self.frame_14)
        self.drinks.setMinimumSize(QtCore.QSize(0, 50))
        self.drinks.setMaximumSize(QtCore.QSize(16777215, 50))
        self.drinks.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.drinks.setStyleSheet("background-color: rgb(192, 216, 192);\n"
"")
        self.drinks.setObjectName("drinks")
        self.verticalLayout_6.addWidget(self.drinks)
        self.others = QtWidgets.QPushButton(self.frame_14)
        self.others.setMinimumSize(QtCore.QSize(0, 50))
        self.others.setMaximumSize(QtCore.QSize(16777215, 50))
        self.others.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.others.setStyleSheet("background-color: rgb(192, 216, 192);")
        self.others.setObjectName("others")
        self.verticalLayout_6.addWidget(self.others)
        self.verticalLayout_5.addWidget(self.frame_14, 0, QtCore.Qt.AlignTop)
        self.horizontalLayout_12.addWidget(self.sideBar)
        self.main = QtWidgets.QStackedWidget(self.menu)
        self.main.setObjectName("main")
        self.page = QtWidgets.QWidget()
        self.page.setObjectName("page")
        self.verticalLayout_10 = QtWidgets.QVBoxLayout(self.page)
        self.verticalLayout_10.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_10.setSpacing(0)
        self.verticalLayout_10.setObjectName("verticalLayout_10")
        self.scrollArea = QtWidgets.QScrollArea(self.page)
        self.scrollArea.setMinimumSize(QtCore.QSize(0, 579))
        self.scrollArea.setMaximumSize(QtCore.QSize(16777215, 579))
        self.scrollArea.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.scrollArea.setWidgetResizable(True)
        self.scrollArea.setAlignment(QtCore.Qt.AlignLeading|QtCore.Qt.AlignLeft|QtCore.Qt.AlignVCenter)
        self.scrollArea.setObjectName("scrollArea")
        self.scrollAreaWidgetContents = QtWidgets.QWidget()
        self.scrollAreaWidgetContents.setGeometry(QtCore.QRect(0, 0, 711, 620))
        self.scrollAreaWidgetContents.setObjectName("scrollAreaWidgetContents")
        self.gridLayout = QtWidgets.QGridLayout(self.scrollAreaWidgetContents)
        self.gridLayout.setObjectName("gridLayout")
        self.frame_21 = QtWidgets.QFrame(self.scrollAreaWidgetContents)
        self.frame_21.setMinimumSize(QtCore.QSize(150, 200))
        self.frame_21.setMaximumSize(QtCore.QSize(150, 200))
        self.frame_21.setFrameShape(QtWidgets.QFrame.WinPanel)
        self.frame_21.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_21.setLineWidth(1)
        self.frame_21.setObjectName("frame_21")
        self.gridLayout.addWidget(self.frame_21, 1, 1, 1, 1)
        self.frame_22 = QtWidgets.QFrame(self.scrollAreaWidgetContents)
        self.frame_22.setMinimumSize(QtCore.QSize(150, 200))
        self.frame_22.setMaximumSize(QtCore.QSize(150, 200))
        self.frame_22.setFrameShape(QtWidgets.QFrame.WinPanel)
        self.frame_22.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_22.setLineWidth(1)
        self.frame_22.setObjectName("frame_22")
        self.gridLayout.addWidget(self.frame_22, 3, 0, 1, 1)
        self.frame_4 = QtWidgets.QFrame(self.scrollAreaWidgetContents)
        self.frame_4.setMinimumSize(QtCore.QSize(150, 200))
        self.frame_4.setMaximumSize(QtCore.QSize(150, 200))
        self.frame_4.setFrameShape(QtWidgets.QFrame.WinPanel)
        self.frame_4.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_4.setLineWidth(1)
        self.frame_4.setObjectName("frame_4")
        self.gridLayout.addWidget(self.frame_4, 1, 2, 1, 1)
        self.frame_20 = QtWidgets.QFrame(self.scrollAreaWidgetContents)
        self.frame_20.setMinimumSize(QtCore.QSize(150, 200))
        self.frame_20.setMaximumSize(QtCore.QSize(150, 200))
        self.frame_20.setFrameShape(QtWidgets.QFrame.WinPanel)
        self.frame_20.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_20.setLineWidth(1)
        self.frame_20.setObjectName("frame_20")
        self.gridLayout.addWidget(self.frame_20, 1, 0, 1, 1)
        self.frame_5 = QtWidgets.QFrame(self.scrollAreaWidgetContents)
        self.frame_5.setMinimumSize(QtCore.QSize(150, 200))
        self.frame_5.setMaximumSize(QtCore.QSize(150, 200))
        self.frame_5.setFrameShape(QtWidgets.QFrame.WinPanel)
        self.frame_5.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_5.setObjectName("frame_5")
        self.gridLayout.addWidget(self.frame_5, 1, 3, 1, 1)
        self.frame_6 = QtWidgets.QFrame(self.scrollAreaWidgetContents)
        self.frame_6.setMinimumSize(QtCore.QSize(150, 200))
        self.frame_6.setMaximumSize(QtCore.QSize(150, 200))
        self.frame_6.setFrameShape(QtWidgets.QFrame.WinPanel)
        self.frame_6.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_6.setLineWidth(1)
        self.frame_6.setObjectName("frame_6")
        self.gridLayout.addWidget(self.frame_6, 3, 2, 1, 1)
        self.frame_9 = QtWidgets.QFrame(self.scrollAreaWidgetContents)
        self.frame_9.setMinimumSize(QtCore.QSize(150, 200))
        self.frame_9.setMaximumSize(QtCore.QSize(150, 200))
        self.frame_9.setFrameShape(QtWidgets.QFrame.WinPanel)
        self.frame_9.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_9.setObjectName("frame_9")
        self.gridLayout.addWidget(self.frame_9, 2, 3, 1, 1)
        self.frame_10 = QtWidgets.QFrame(self.scrollAreaWidgetContents)
        self.frame_10.setMinimumSize(QtCore.QSize(150, 200))
        self.frame_10.setMaximumSize(QtCore.QSize(150, 200))
        self.frame_10.setFrameShape(QtWidgets.QFrame.WinPanel)
        self.frame_10.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_10.setObjectName("frame_10")
        self.gridLayout.addWidget(self.frame_10, 3, 3, 1, 1)
        self.frame_23 = QtWidgets.QFrame(self.scrollAreaWidgetContents)
        self.frame_23.setMinimumSize(QtCore.QSize(150, 200))
        self.frame_23.setMaximumSize(QtCore.QSize(150, 200))
        self.frame_23.setFrameShape(QtWidgets.QFrame.WinPanel)
        self.frame_23.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_23.setLineWidth(1)
        self.frame_23.setObjectName("frame_23")
        self.gridLayout.addWidget(self.frame_23, 2, 0, 1, 1)
        self.frame_24 = QtWidgets.QFrame(self.scrollAreaWidgetContents)
        self.frame_24.setMinimumSize(QtCore.QSize(150, 200))
        self.frame_24.setMaximumSize(QtCore.QSize(150, 200))
        self.frame_24.setFrameShape(QtWidgets.QFrame.WinPanel)
        self.frame_24.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_24.setLineWidth(1)
        self.frame_24.setObjectName("frame_24")
        self.gridLayout.addWidget(self.frame_24, 2, 1, 1, 1)
        self.frame_17 = QtWidgets.QFrame(self.scrollAreaWidgetContents)
        self.frame_17.setMinimumSize(QtCore.QSize(150, 200))
        self.frame_17.setMaximumSize(QtCore.QSize(150, 200))
        self.frame_17.setFrameShape(QtWidgets.QFrame.WinPanel)
        self.frame_17.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_17.setLineWidth(1)
        self.frame_17.setObjectName("frame_17")
        self.gridLayout.addWidget(self.frame_17, 2, 2, 1, 1)
        self.frame_18 = QtWidgets.QFrame(self.scrollAreaWidgetContents)
        self.frame_18.setMinimumSize(QtCore.QSize(150, 200))
        self.frame_18.setMaximumSize(QtCore.QSize(150, 200))
        self.frame_18.setFrameShape(QtWidgets.QFrame.WinPanel)
        self.frame_18.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_18.setLineWidth(1)
        self.frame_18.setObjectName("frame_18")
        self.gridLayout.addWidget(self.frame_18, 3, 1, 1, 1)
        self.scrollArea.setWidget(self.scrollAreaWidgetContents)
        self.verticalLayout_10.addWidget(self.scrollArea)
        self.main.addWidget(self.page)
        self.page_2 = QtWidgets.QWidget()
        self.page_2.setObjectName("page_2")
        self.main.addWidget(self.page_2)
        self.horizontalLayout_12.addWidget(self.main)
        self.stackedWidget.addWidget(self.menu)
        self.bills = QtWidgets.QWidget()
        self.bills.setObjectName("bills")
        self.horizontalLayout_13 = QtWidgets.QHBoxLayout(self.bills)
        self.horizontalLayout_13.setContentsMargins(10, 0, 0, 5)
        self.horizontalLayout_13.setObjectName("horizontalLayout_13")
        self.frame_13 = QtWidgets.QFrame(self.bills)
        self.frame_13.setMinimumSize(QtCore.QSize(0, 0))
        self.frame_13.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.frame_13.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.frame_13.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_13.setLineWidth(3)
        self.frame_13.setObjectName("frame_13")
        self.verticalLayout_7 = QtWidgets.QVBoxLayout(self.frame_13)
        self.verticalLayout_7.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_7.setSpacing(0)
        self.verticalLayout_7.setObjectName("verticalLayout_7")
        self.frame_15 = QtWidgets.QFrame(self.frame_13)
        self.frame_15.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_15.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_15.setObjectName("frame_15")
        self.verticalLayout_8 = QtWidgets.QVBoxLayout(self.frame_15)
        self.verticalLayout_8.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_8.setSpacing(20)
        self.verticalLayout_8.setObjectName("verticalLayout_8")
        self.pushButton_12 = QtWidgets.QPushButton(self.frame_15)
        self.pushButton_12.setMinimumSize(QtCore.QSize(0, 50))
        self.pushButton_12.setMaximumSize(QtCore.QSize(16777215, 50))
        self.pushButton_12.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.pushButton_12.setObjectName("pushButton_12")
        self.verticalLayout_8.addWidget(self.pushButton_12)
        self.pushButton_13 = QtWidgets.QPushButton(self.frame_15)
        self.pushButton_13.setMinimumSize(QtCore.QSize(0, 50))
        self.pushButton_13.setMaximumSize(QtCore.QSize(16777215, 50))
        self.pushButton_13.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.pushButton_13.setObjectName("pushButton_13")
        self.verticalLayout_8.addWidget(self.pushButton_13)
        self.verticalLayout_7.addWidget(self.frame_15, 0, QtCore.Qt.AlignTop)
        self.horizontalLayout_13.addWidget(self.frame_13, 0, QtCore.Qt.AlignLeft)
        self.frame_16 = QtWidgets.QFrame(self.bills)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.frame_16.sizePolicy().hasHeightForWidth())
        self.frame_16.setSizePolicy(sizePolicy)
        self.frame_16.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_16.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_16.setObjectName("frame_16")
        self.horizontalLayout_13.addWidget(self.frame_16)
        self.stackedWidget.addWidget(self.bills)
        self.verticalLayout_4.addWidget(self.stackedWidget)
        self.verticalLayout_3.addWidget(self.main_2)
        self.horizontalLayout_5.addWidget(self.leftMenu)
        self.rightMenu = QtWidgets.QFrame(self.body)
        self.rightMenu.setMinimumSize(QtCore.QSize(400, 650))
        self.rightMenu.setMaximumSize(QtCore.QSize(400, 650))
        self.rightMenu.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.rightMenu.setFrameShadow(QtWidgets.QFrame.Raised)
        self.rightMenu.setLineWidth(3)
        self.rightMenu.setObjectName("rightMenu")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.rightMenu)
        self.verticalLayout_2.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_2.setSpacing(0)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.topbar_2 = QtWidgets.QFrame(self.rightMenu)
        self.topbar_2.setMinimumSize(QtCore.QSize(0, 60))
        self.topbar_2.setMaximumSize(QtCore.QSize(16777215, 60))
        self.topbar_2.setStyleSheet("background-color: rgb(185, 215, 234);")
        self.topbar_2.setFrameShape(QtWidgets.QFrame.WinPanel)
        self.topbar_2.setFrameShadow(QtWidgets.QFrame.Raised)
        self.topbar_2.setLineWidth(3)
        self.topbar_2.setObjectName("topbar_2")
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout(self.topbar_2)
        self.horizontalLayout_6.setContentsMargins(-1, 5, 0, 0)
        self.horizontalLayout_6.setSpacing(20)
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        self.label_2 = QtWidgets.QLabel(self.topbar_2)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_6.addWidget(self.label_2)
        self.comboBox = QtWidgets.QComboBox(self.topbar_2)
        self.comboBox.setMinimumSize(QtCore.QSize(0, 27))
        self.comboBox.setMaximumSize(QtCore.QSize(16777215, 27))
        self.comboBox.setStyleSheet("background-color: rgb(192, 216, 192);")
        self.comboBox.setEditable(False)
        self.comboBox.setCurrentText("")
        self.comboBox.setObjectName("comboBox")
        self.horizontalLayout_6.addWidget(self.comboBox)
        self.verticalLayout_2.addWidget(self.topbar_2, 0, QtCore.Qt.AlignTop)
        self.frame_7 = QtWidgets.QFrame(self.rightMenu)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.frame_7.sizePolicy().hasHeightForWidth())
        self.frame_7.setSizePolicy(sizePolicy)
        self.frame_7.setMinimumSize(QtCore.QSize(0, 0))
        self.frame_7.setFrameShape(QtWidgets.QFrame.WinPanel)
        self.frame_7.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_7.setLineWidth(3)
        self.frame_7.setObjectName("frame_7")
        self.horizontalLayout_11 = QtWidgets.QHBoxLayout(self.frame_7)
        self.horizontalLayout_11.setContentsMargins(10, 0, 0, 0)
        self.horizontalLayout_11.setSpacing(0)
        self.horizontalLayout_11.setObjectName("horizontalLayout_11")
        self.label_5 = QtWidgets.QLabel(self.frame_7)
        font = QtGui.QFont()
        font.setPointSize(30)
        self.label_5.setFont(font)
        self.label_5.setObjectName("label_5")
        self.horizontalLayout_11.addWidget(self.label_5)
        self.verticalLayout_2.addWidget(self.frame_7)
        self.frame_8 = QtWidgets.QFrame(self.rightMenu)
        self.frame_8.setMinimumSize(QtCore.QSize(396, 80))
        self.frame_8.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.frame_8.setFrameShape(QtWidgets.QFrame.Panel)
        self.frame_8.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_8.setLineWidth(3)
        self.frame_8.setObjectName("frame_8")
        self.horizontalLayout_7 = QtWidgets.QHBoxLayout(self.frame_8)
        self.horizontalLayout_7.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_7.setSpacing(20)
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        self.label_3 = QtWidgets.QLabel(self.frame_8)
        self.label_3.setAlignment(QtCore.Qt.AlignCenter)
        self.label_3.setObjectName("label_3")
        self.horizontalLayout_7.addWidget(self.label_3)
        self.label_4 = QtWidgets.QLabel(self.frame_8)
        self.label_4.setObjectName("label_4")
        self.horizontalLayout_7.addWidget(self.label_4)
        self.verticalLayout_2.addWidget(self.frame_8)
        self.horizontalLayout_5.addWidget(self.rightMenu)
        self.verticalLayout.addWidget(self.body)
        self.footer = QtWidgets.QFrame(self.centralwidget)
        self.footer.setMinimumSize(QtCore.QSize(0, 200))
        self.footer.setMaximumSize(QtCore.QSize(16777215, 200))
        self.footer.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.footer.setFrameShadow(QtWidgets.QFrame.Raised)
        self.footer.setObjectName("footer")
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout(self.footer)
        self.horizontalLayout_3.setContentsMargins(0, 10, 0, 0)
        self.horizontalLayout_3.setSpacing(0)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.frame = QtWidgets.QFrame(self.footer)
        self.frame.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame.setObjectName("frame")
        self.horizontalLayout_3.addWidget(self.frame)
        self.frame_2 = QtWidgets.QFrame(self.footer)
        self.frame_2.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.frame_2.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_2.setObjectName("frame_2")
        self.horizontalLayout_3.addWidget(self.frame_2)
        self.frame_3 = QtWidgets.QFrame(self.footer)
        self.frame_3.setMinimumSize(QtCore.QSize(400, 200))
        self.frame_3.setMaximumSize(QtCore.QSize(400, 200))
        self.frame_3.setFrameShape(QtWidgets.QFrame.Panel)
        self.frame_3.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_3.setLineWidth(5)
        self.frame_3.setObjectName("frame_3")
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout(self.frame_3)
        self.horizontalLayout_4.setContentsMargins(10, 5, 10, 5)
        self.horizontalLayout_4.setSpacing(20)
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.pushButton = QtWidgets.QPushButton(self.frame_3)
        self.pushButton.setMinimumSize(QtCore.QSize(0, 130))
        self.pushButton.setMaximumSize(QtCore.QSize(16777215, 130))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.pushButton.setFont(font)
        self.pushButton.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.pushButton.setStyleSheet("background-color: rgb(195, 174, 214);")
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap(":/newPrefix/icons/cil-print.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.pushButton.setIcon(icon3)
        self.pushButton.setIconSize(QtCore.QSize(16, 30))
        self.pushButton.setObjectName("pushButton")
        self.horizontalLayout_4.addWidget(self.pushButton)
        self.pushButton_2 = QtWidgets.QPushButton(self.frame_3)
        self.pushButton_2.setMinimumSize(QtCore.QSize(0, 130))
        self.pushButton_2.setMaximumSize(QtCore.QSize(16777215, 130))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.pushButton_2.setFont(font)
        self.pushButton_2.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.pushButton_2.setStyleSheet("background-color: rgb(195, 174, 214);")
        icon4 = QtGui.QIcon()
        icon4.addPixmap(QtGui.QPixmap(":/newPrefix/icons/cil-save.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.pushButton_2.setIcon(icon4)
        self.pushButton_2.setIconSize(QtCore.QSize(16, 30))
        self.pushButton_2.setObjectName("pushButton_2")
        self.horizontalLayout_4.addWidget(self.pushButton_2)
        self.pushButton_3 = QtWidgets.QPushButton(self.frame_3)
        self.pushButton_3.setMinimumSize(QtCore.QSize(0, 130))
        self.pushButton_3.setMaximumSize(QtCore.QSize(16777215, 130))
        font = QtGui.QFont()
        font.setPointSize(12)
        self.pushButton_3.setFont(font)
        self.pushButton_3.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.pushButton_3.setStyleSheet("background-color: rgb(195, 174, 214);")
        icon5 = QtGui.QIcon()
        icon5.addPixmap(QtGui.QPixmap(":/newPrefix/icons/cil-credit-card.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.pushButton_3.setIcon(icon5)
        self.pushButton_3.setIconSize(QtCore.QSize(16, 30))
        self.pushButton_3.setObjectName("pushButton_3")
        self.horizontalLayout_4.addWidget(self.pushButton_3)
        self.horizontalLayout_3.addWidget(self.frame_3)
        self.verticalLayout.addWidget(self.footer, 0, QtCore.Qt.AlignBottom)
        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        self.stackedWidget.setCurrentIndex(0)
        self.main.setCurrentIndex(0)
        self.comboBox.setCurrentIndex(-1)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.label.setText(_translate("MainWindow", "TITLE"))
        self.menuButton.setText(_translate("MainWindow", "Menu"))
        self.billsButton.setText(_translate("MainWindow", "Bills"))
        self.pushButton_6.setText(_translate("MainWindow", "Search"))
        self.pushButton_8.setText(_translate("MainWindow", "Edit"))
        self.pushButton_7.setText(_translate("MainWindow", "Logout"))
        self.foods.setText(_translate("MainWindow", "Foods"))
        self.drinks.setText(_translate("MainWindow", "Drinks"))
        self.others.setText(_translate("MainWindow", "Others"))
        self.pushButton_12.setText(_translate("MainWindow", "To Pay"))
        self.pushButton_13.setText(_translate("MainWindow", "Payed"))
        self.label_2.setText(_translate("MainWindow", "Table:"))
        self.label_5.setText(_translate("MainWindow", "LIST"))
        self.label_3.setText(_translate("MainWindow", "Total:"))
        self.label_4.setText(_translate("MainWindow", "TextLabel"))
        self.pushButton.setText(_translate("MainWindow", "Print"))
        self.pushButton_2.setText(_translate("MainWindow", "Save"))
        self.pushButton_3.setText(_translate("MainWindow", "Pay"))
import resources_rc


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
