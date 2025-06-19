package com.pubmatic.sdk.common.browser;

import android.content.DialogInterface;
import android.webkit.SslErrorHandler;
import com.pubmatic.sdk.common.browser.POBInternalBrowserActivity;

/* loaded from: classes2.dex */
public class b implements com.pubmatic.sdk.common.utility.b {
    final /* synthetic */ SslErrorHandler a;
    final /* synthetic */ POBInternalBrowserActivity.f b;

    public b(POBInternalBrowserActivity.f fVar, SslErrorHandler sslErrorHandler) {
        this.b = fVar;
        this.a = sslErrorHandler;
    }

    @Override // com.pubmatic.sdk.common.utility.b
    public void onCancel(DialogInterface dialogInterface, int i) {
        dialogInterface.dismiss();
        this.a.cancel();
        if (POBInternalBrowserActivity.this.d == null || POBInternalBrowserActivity.this.d.copyBackForwardList().getCurrentIndex() >= 0) {
            return;
        }
        POBInternalBrowserActivity.this.l();
    }

    @Override // com.pubmatic.sdk.common.utility.b
    public void onSuccess(DialogInterface dialogInterface, int i) {
        dialogInterface.dismiss();
        this.a.proceed();
    }
}
