package com.quizlet.uicommon.ui.common.widgets;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ QFormField b;

    public /* synthetic */ c(QFormField qFormField, int i) {
        this.a = i;
        this.b = qFormField;
    }

    @Override // java.lang.Runnable
    public final void run() {
        QFormField qFormField = this.b;
        switch (this.a) {
            case 0:
                QFormField.a(qFormField);
                break;
            default:
                int[] iArr = QFormField.u;
                qFormField.refreshDrawableState();
                qFormField.h();
                qFormField.g();
                break;
        }
    }
}
