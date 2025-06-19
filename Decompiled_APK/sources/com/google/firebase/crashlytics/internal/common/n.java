package com.google.firebase.crashlytics.internal.common;

/* loaded from: classes2.dex */
public final /* synthetic */ class n implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ q b;
    public final /* synthetic */ com.google.android.datatransport.cct.internal.s c;

    public /* synthetic */ n(q qVar, com.google.android.datatransport.cct.internal.s sVar, int i) {
        this.a = i;
        this.b = qVar;
        this.c = sVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.a(this.c);
                break;
            default:
                this.b.a(this.c);
                break;
        }
    }
}
