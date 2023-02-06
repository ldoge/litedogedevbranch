// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/walletview.h>

#include <node/psbt.h>
#include <node/transaction.h>
#include <policy/policy.h>
#include <qt/addressbookpage.h>
#include <qt/askpassphrasedialog.h>
#include <qt/clientmodel.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/overviewpage.h>
#include <qt/platformstyle.h>
#include <qt/receivecoinsdialog.h>
#include <qt/sendcoinsdialog.h>
#include <qt/signverifymessagedialog.h>
#include <qt/transactiontablemodel.h>
#include <qt/transactionview.h>
#include <qt/walletmodel.h>

#include <interfaces/node.h>
#include <node/interface_ui.h>
#include <util/strencodings.h>

#include <qt/mintingview.h>
#include <wallet/wallet.h>

#include <QAction>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QProgressDialog>
#include <QPushButton>
#include <QVBoxLayout>

WalletView::WalletView(WalletModel* wallet_model, const PlatformStyle* _platformStyle, QWidget* parent)
    : QStackedWidget(parent),
      walletModel(wallet_model),
      platformStyle(_platformStyle)
{
    assert(walletModel);

    // Create tabs
    overviewPage = new OverviewPage(platformStyle);
    overviewPage->setWalletModel(walletModel);

    transactionsPage = new QWidget(this);
    QVBoxLayout *vbox = new QVBoxLayout();
    QHBoxLayout *hbox_buttons = new QHBoxLayout();
    transactionView = new TransactionView(platformStyle, this);
    transactionView->setModel(walletModel);

    vbox->addWidget(transactionView);
    QPushButton *exportButton = new QPushButton(tr("&Export"), this);
    exportButton->setToolTip(tr("Export the data in the current tab to a file"));
    if (platformStyle->getImagesOnButtons()) {
        exportButton->setIcon(QIcon(":/icons/export"));
    }
    hbox_buttons->addStretch();
    hbox_buttons->addWidget(exportButton);
    vbox->addLayout(hbox_buttons);
    transactionsPage->setLayout(vbox);

    mintingPage = new QWidget(this);
    QVBoxLayout *vboxMinting = new QVBoxLayout();
    mintingView = new MintingView(this);
    mintingView->setModel(walletModel);

    vboxMinting->addWidget(mintingView);
    mintingPage->setLayout(vboxMinting);

    receiveCoinsPage = new ReceiveCoinsDialog(platformStyle);
    receiveCoinsPage->setModel(walletModel);

    sendCoinsPage = new SendCoinsDialog(platformStyle);
    sendCoinsPage->setModel(walletModel);

    usedSendingAddressesPage = new AddressBookPage(platformStyle, AddressBookPage::ForEditing, AddressBookPage::SendingTab, this);
    usedSendingAddressesPage->setModel(walletModel->getAddressTableModel());

    usedReceivingAddressesPage = new AddressBookPage(platformStyle, AddressBookPage::ForEditing, AddressBookPage::ReceivingTab, this);
    usedReceivingAddressesPage->setModel(walletModel->getAddressTableModel());

    addWidget(overviewPage);
    addWidget(transactionsPage);
    addWidget(mintingPage);
    addWidget(receiveCoinsPage);
    addWidget(sendCoinsPage);

    connect(overviewPage, &OverviewPage::transactionClicked, this, &WalletView::transactionClicked);
    // Clicking on a transaction on the overview pre-selects the transaction on the transaction history page
    connect(overviewPage, &OverviewPage::transactionClicked, transactionView, qOverload<const QModelIndex&>(&TransactionView::focusTransaction));

    connect(overviewPage, &OverviewPage::outOfSyncWarningClicked, this, &WalletView::outOfSyncWarningClicked);

    connect(sendCoinsPage, &SendCoinsDialog::coinsSent, this, &WalletView::coinsSent);
    // Highlight transaction after send
    connect(sendCoinsPage, &SendCoinsDialog::coinsSent, transactionView, qOverload<const uint256&>(&TransactionView::focusTransaction));

    // Clicking on "Export" allows to export the transaction list
    connect(exportButton, &QPushButton::clicked, transactionView, &TransactionView::exportClicked);

    // Pass through messages from sendCoinsPage
    connect(sendCoinsPage, &SendCoinsDialog::message, this, &WalletView::message);
    // Pass through messages from transactionView
    connect(transactionView, &TransactionView::message, this, &WalletView::message);

    connect(this, &WalletView::setPrivacy, overviewPage, &OverviewPage::setPrivacy);
    connect(this, &WalletView::setPrivacy, this, &WalletView::disableTransactionView);

    // Receive and pass through messages from wallet model
    connect(walletModel, &WalletModel::message, this, &WalletView::message);

    // Handle changes in encryption status
    connect(walletModel, &WalletModel::encryptionStatusChanged, this, &WalletView::encryptionStatusChanged);

    // Balloon pop-up for new transaction
    connect(walletModel->getTransactionTableModel(), &TransactionTableModel::rowsInserted, this, &WalletView::processNewTransaction);

    // Ask for passphrase if needed
    connect(walletModel, &WalletModel::requireUnlock, this, &WalletView::unlockWallet);

    // Show progress dialog
    connect(walletModel, &WalletModel::showProgress, this, &WalletView::showProgress);

    this->decryptForMinting(true);
}

WalletView::~WalletView() = default;

void WalletView::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;

    overviewPage->setClientModel(_clientModel);
    sendCoinsPage->setClientModel(_clientModel);
    walletModel->setClientModel(_clientModel);
    //mintingView->setClientModel(_clientModel);
}

void WalletView::processNewTransaction(const QModelIndex& parent, int start, int /*end*/)
{
    // Prevent balloon-spam when initial block download is in progress
    if (!clientModel || clientModel->node().isInitialBlockDownload()) {
        return;
    }

    TransactionTableModel *ttm = walletModel->getTransactionTableModel();
    if (!ttm || ttm->processingQueuedTransactions())
        return;

    QString date = ttm->index(start, TransactionTableModel::Date, parent).data().toString();
    qint64 amount = ttm->index(start, TransactionTableModel::Amount, parent).data(Qt::EditRole).toULongLong();
    QString type = ttm->index(start, TransactionTableModel::Type, parent).data().toString();
    QModelIndex index = ttm->index(start, 0, parent);
    QString address = ttm->data(index, TransactionTableModel::AddressRole).toString();
    QString label = GUIUtil::HtmlEscape(ttm->data(index, TransactionTableModel::LabelRole).toString());

    Q_EMIT incomingTransaction(date, walletModel->getOptionsModel()->getDisplayUnit(), amount, type, address, label, GUIUtil::HtmlEscape(walletModel->getWalletName()));
}

void WalletView::gotoOverviewPage()
{
    setCurrentWidget(overviewPage);
}

void WalletView::gotoHistoryPage()
{
    setCurrentWidget(transactionsPage);
}

void WalletView::gotoMintingPage()
{
    setCurrentWidget(mintingPage);
}

void WalletView::gotoReceiveCoinsPage()
{
    setCurrentWidget(receiveCoinsPage);
}

void WalletView::gotoSendCoinsPage(QString addr)
{
    setCurrentWidget(sendCoinsPage);

    if (!addr.isEmpty())
        sendCoinsPage->setAddress(addr);
}

void WalletView::gotoSignMessageTab(QString addr)
{
    // calls show() in showTab_SM()
    SignVerifyMessageDialog *signVerifyMessageDialog = new SignVerifyMessageDialog(platformStyle, this);
    signVerifyMessageDialog->setAttribute(Qt::WA_DeleteOnClose);
    signVerifyMessageDialog->setModel(walletModel);
    signVerifyMessageDialog->showTab_SM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_SM(addr);
}

void WalletView::gotoVerifyMessageTab(QString addr)
{
    // calls show() in showTab_VM()
    SignVerifyMessageDialog *signVerifyMessageDialog = new SignVerifyMessageDialog(platformStyle, this);
    signVerifyMessageDialog->setAttribute(Qt::WA_DeleteOnClose);
    signVerifyMessageDialog->setModel(walletModel);
    signVerifyMessageDialog->showTab_VM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_VM(addr);
}

void WalletView::gotoLoadPSBT(bool from_clipboard)
{
    std::string data;

    if (from_clipboard) {
        std::string raw = QApplication::clipboard()->text().toStdString();
        bool invalid;
        data = DecodeBase64(raw, &invalid);
        if (invalid) {
            Q_EMIT message(tr("Error"), tr("Unable to decode PSBT from clipboard (invalid base64)"), CClientUIInterface::MSG_ERROR);
            return;
        }
    } else {
        QString filename = GUIUtil::getOpenFileName(this,
            tr("Load Transaction Data"), QString(),
            tr("Partially Signed Transaction (*.psbt)"), nullptr);
        if (filename.isEmpty()) return;
        if (GetFileSize(filename.toLocal8Bit().data(), MAX_FILE_SIZE_PSBT) == MAX_FILE_SIZE_PSBT) {
            Q_EMIT message(tr("Error"), tr("PSBT file must be smaller than 100 MiB"), CClientUIInterface::MSG_ERROR);
            return;
        }
        std::ifstream in(filename.toLocal8Bit().data(), std::ios::binary);
        data = std::string(std::istreambuf_iterator<char>{in}, {});
    }

    std::string error;
    PartiallySignedTransaction psbtx;
    if (!DecodeRawPSBT(psbtx, data, error)) {
        Q_EMIT message(tr("Error"), tr("Unable to decode PSBT") + "\n" + QString::fromStdString(error), CClientUIInterface::MSG_ERROR);
        return;
    }

    CMutableTransaction mtx;
    bool complete = false;
    PSBTAnalysis analysis = AnalyzePSBT(psbtx);
    QMessageBox msgBox;
    msgBox.setText("PSBT");
    switch (analysis.next) {
    case PSBTRole::CREATOR:
    case PSBTRole::UPDATER:
        msgBox.setInformativeText("PSBT is incomplete. Copy to clipboard for manual inspection?");
        break;
    case PSBTRole::SIGNER:
        msgBox.setInformativeText("Transaction needs more signatures. Copy to clipboard?");
        break;
    case PSBTRole::FINALIZER:
    case PSBTRole::EXTRACTOR:
        complete = FinalizeAndExtractPSBT(psbtx, mtx);
        if (complete) {
            msgBox.setInformativeText(tr("Would you like to send this transaction?"));
        } else {
            // The analyzer missed something, e.g. if there are final_scriptSig/final_scriptWitness
            // but with invalid signatures.
            msgBox.setInformativeText(tr("There was an unexpected problem processing the PSBT. Copy to clipboard for manual inspection?"));
        }
    }

    msgBox.setStandardButtons(QMessageBox::Yes | QMessageBox::Cancel);
    switch (msgBox.exec()) {
    case QMessageBox::Yes: {
        if (complete) {
            std::string err_string;
            CTransactionRef tx = MakeTransactionRef(mtx);

            TransactionError result = BroadcastTransaction(*clientModel->node().context(), tx, err_string, DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK(), /* relay */ true, /* wait_callback */ false);
            if (result == TransactionError::OK) {
                Q_EMIT message(tr("Success"), tr("Broadcasted transaction sucessfully."), CClientUIInterface::MSG_INFORMATION | CClientUIInterface::MODAL);
            } else {
                Q_EMIT message(tr("Error"), QString::fromStdString(err_string), CClientUIInterface::MSG_ERROR);
            }
        } else {
            // Serialize the PSBT
            CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
            ssTx << psbtx;
            GUIUtil::setClipboard(EncodeBase64(ssTx.str()).c_str());
            Q_EMIT message(tr("PSBT copied"), "Copied to clipboard", CClientUIInterface::MSG_INFORMATION);
            return;
        }
    }
    case QMessageBox::Cancel:
        break;
    default:
        assert(false);
    }
}

bool WalletView::handlePaymentRequest(const SendCoinsRecipient& recipient)
{
    return sendCoinsPage->handlePaymentRequest(recipient);
}

void WalletView::showOutOfSyncWarning(bool fShow)
{
    overviewPage->showOutOfSyncWarning(fShow);
}

void WalletView::encryptWallet()
{
    auto dlg = new AskPassphraseDialog(AskPassphraseDialog::Encrypt, this);
    dlg->setModel(walletModel);
    connect(dlg, &QDialog::finished, this, &WalletView::encryptionStatusChanged);
    GUIUtil::ShowModalDialogAsynchronously(dlg);
}

void WalletView::decryptForMinting(bool status)
{
    if(!walletModel)
        return;

    if (status)
    {
        if(walletModel->getEncryptionStatus() != WalletModel::Locked)
            return;

        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, this);
        dlg.setModel(walletModel);
        dlg.exec();

        if(walletModel->getEncryptionStatus() != WalletModel::Unlocked)
            return;

        wallet::fWalletUnlockMintOnly = true;
    }
    else
    {
        if(walletModel->getEncryptionStatus() != WalletModel::Unlocked)
            return;

        if (!wallet::fWalletUnlockMintOnly)
            return;

        walletModel->setWalletLocked(true);
        wallet::fWalletUnlockMintOnly = false;
    }
}
void WalletView::backupWallet()
{
    QString filename = GUIUtil::getSaveFileName(this,
        tr("Backup Wallet"), QString(),
        //: Name of the wallet data file format.
        tr("Wallet Data") + QLatin1String(" (*.dat)"), nullptr);

    if (filename.isEmpty())
        return;

    if (!walletModel->wallet().backupWallet(filename.toLocal8Bit().data())) {
        Q_EMIT message(tr("Backup Failed"), tr("There was an error trying to save the wallet data to %1.").arg(filename),
            CClientUIInterface::MSG_ERROR);
        }
    else {
        Q_EMIT message(tr("Backup Successful"), tr("The wallet data was successfully saved to %1.").arg(filename),
            CClientUIInterface::MSG_INFORMATION);
    }
}

void WalletView::changePassphrase()
{
    auto dlg = new AskPassphraseDialog(AskPassphraseDialog::ChangePass, this);
    dlg->setModel(walletModel);
    GUIUtil::ShowModalDialogAsynchronously(dlg);
}

void WalletView::unlockWallet()
{
    // Unlock wallet when requested by wallet model
    if (walletModel->getEncryptionStatus() == WalletModel::Locked) {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, this);
        dlg.setModel(walletModel);
        // A modal dialog must be synchronous here as expected
        // in the WalletModel::requestUnlock() function.
        dlg.exec();
    }
}

void WalletView::usedSendingAddresses()
{
    GUIUtil::bringToFront(usedSendingAddressesPage);
}

void WalletView::usedReceivingAddresses()
{
    GUIUtil::bringToFront(usedReceivingAddressesPage);
}

void WalletView::showProgress(const QString &title, int nProgress)
{
    if (nProgress == 0) {
        progressDialog = new QProgressDialog(title, tr("Cancel"), 0, 100);
        GUIUtil::PolishProgressDialog(progressDialog);
        progressDialog->setWindowModality(Qt::ApplicationModal);
        progressDialog->setAutoClose(false);
        progressDialog->setValue(0);
    } else if (nProgress == 100) {
        if (progressDialog) {
            progressDialog->close();
            progressDialog->deleteLater();
            progressDialog = nullptr;
        }
    } else if (progressDialog) {
        if (progressDialog->wasCanceled()) {
            getWalletModel()->wallet().abortRescan();
        } else {
            progressDialog->setValue(nProgress);
        }
    }
}

void WalletView::disableTransactionView(bool disable)
{
    transactionView->setDisabled(disable);
}
