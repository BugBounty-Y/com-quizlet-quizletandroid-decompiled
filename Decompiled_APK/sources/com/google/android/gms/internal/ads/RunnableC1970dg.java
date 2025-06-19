package com.google.android.gms.internal.ads;

import androidx.collection.C0208f;

/* renamed from: com.google.android.gms.internal.ads.dg, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC1970dg implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ InterfaceC2529qe b;

    public /* synthetic */ RunnableC1970dg(InterfaceC2529qe interfaceC2529qe, int i) {
        this.a = i;
        this.b = interfaceC2529qe;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.onResume();
                break;
            case 1:
                this.b.onPause();
                break;
            case 2:
                this.b.destroy();
                break;
            case 3:
                this.b.j("onSdkImpression", new C0208f(0));
                break;
            case 4:
                this.b.destroy();
                break;
            default:
                this.b.U();
                break;
        }
    }
}
