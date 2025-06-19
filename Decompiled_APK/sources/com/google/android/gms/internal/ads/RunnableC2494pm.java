package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.pm, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC2494pm implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Hr b;

    public /* synthetic */ RunnableC2494pm(Hr hr, int i) {
        this.a = i;
        this.b = hr;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.c();
                break;
            default:
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.k5)).booleanValue() && AbstractC1972di.M.b) {
                    this.b.a();
                    break;
                }
                break;
        }
    }
}
