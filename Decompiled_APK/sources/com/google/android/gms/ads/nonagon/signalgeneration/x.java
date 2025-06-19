package com.google.android.gms.ads.nonagon.signalgeneration;

import android.webkit.WebViewClient;

/* loaded from: classes2.dex */
public final /* synthetic */ class x implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ y b;

    public /* synthetic */ x(y yVar, int i) {
        this.a = i;
        this.b = yVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                y yVar = this.b;
                try {
                    com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
                    WebViewClient webViewClient = yVar.a.getWebViewClient();
                    if (webViewClient != yVar) {
                        if (webViewClient != null) {
                            yVar.d = webViewClient;
                        }
                        yVar.a.setWebViewClient(yVar);
                        yVar.x();
                        break;
                    }
                } catch (IllegalStateException unused) {
                    return;
                }
                break;
            default:
                y yVar2 = this.b;
                yVar2.c.execute(new x(yVar2, 0));
                break;
        }
    }
}
