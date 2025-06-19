package com.quizlet.quizletandroid.ui.qrcodes;

import androidx.core.app.AbstractC1016c;
import com.google.android.datatransport.cct.internal.s;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements com.quizlet.uicommon.ui.common.dialogs.f {
    public final /* synthetic */ int a;
    public final /* synthetic */ QLiveQrCodeReaderActivity b;

    public /* synthetic */ b(QLiveQrCodeReaderActivity qLiveQrCodeReaderActivity, int i) {
        this.a = i;
        this.b = qLiveQrCodeReaderActivity;
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.f
    public final void c(com.quizlet.uicommon.ui.common.dialogs.e eVar, int i) {
        QLiveQrCodeReaderActivity qLiveQrCodeReaderActivity = this.b;
        switch (this.a) {
            case 0:
                String str = QLiveQrCodeReaderActivity.t;
                eVar.dismiss();
                QLiveQrCodeReaderActivity qLiveQrCodeReaderActivity2 = (QLiveQrCodeReaderActivity) qLiveQrCodeReaderActivity.c0().h;
                if (qLiveQrCodeReaderActivity2 != null) {
                    qLiveQrCodeReaderActivity2.d0();
                    return;
                } else {
                    Intrinsics.m("view");
                    throw null;
                }
            case 1:
                String str2 = QLiveQrCodeReaderActivity.t;
                eVar.dismiss();
                QLiveQrCodeReaderActivity qLiveQrCodeReaderActivity3 = (QLiveQrCodeReaderActivity) qLiveQrCodeReaderActivity.c0().h;
                if (qLiveQrCodeReaderActivity3 != null) {
                    qLiveQrCodeReaderActivity3.d0();
                    return;
                } else {
                    Intrinsics.m("view");
                    throw null;
                }
            case 2:
                String str3 = QLiveQrCodeReaderActivity.t;
                eVar.dismiss();
                s sVarC0 = qLiveQrCodeReaderActivity.c0();
                QLiveQrCodeReaderActivity qLiveQrCodeReaderActivity4 = (QLiveQrCodeReaderActivity) sVarC0.h;
                if (qLiveQrCodeReaderActivity4 == null) {
                    Intrinsics.m("view");
                    throw null;
                }
                String[] permissions = (String[]) sVarC0.a;
                Intrinsics.checkNotNullParameter(permissions, "permissions");
                AbstractC1016c.g(qLiveQrCodeReaderActivity4, permissions, 1);
                return;
            case 3:
                String str4 = QLiveQrCodeReaderActivity.t;
                eVar.dismiss();
                QLiveQrCodeReaderActivity qLiveQrCodeReaderActivity5 = (QLiveQrCodeReaderActivity) qLiveQrCodeReaderActivity.c0().h;
                if (qLiveQrCodeReaderActivity5 != null) {
                    qLiveQrCodeReaderActivity5.d0();
                    return;
                } else {
                    Intrinsics.m("view");
                    throw null;
                }
            default:
                String str5 = QLiveQrCodeReaderActivity.t;
                eVar.dismiss();
                QLiveQrCodeReaderActivity qLiveQrCodeReaderActivity6 = (QLiveQrCodeReaderActivity) qLiveQrCodeReaderActivity.c0().h;
                if (qLiveQrCodeReaderActivity6 != null) {
                    qLiveQrCodeReaderActivity6.d0();
                    return;
                } else {
                    Intrinsics.m("view");
                    throw null;
                }
        }
    }
}
