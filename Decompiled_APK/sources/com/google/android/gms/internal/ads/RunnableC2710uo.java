package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.uo, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC2710uo implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ C2796wo b;

    public /* synthetic */ RunnableC2710uo(C2796wo c2796wo, int i) {
        this.a = i;
        this.b = c2796wo;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                C2796wo c2796wo = this.b;
                c2796wo.d.execute(new RunnableC2710uo(c2796wo, 1));
                break;
            default:
                C2796wo c2796wo2 = this.b;
                c2796wo2.a.set(new C2753vo(c2796wo2.e.zzb(), c2796wo2.f, c2796wo2.c));
                break;
        }
    }
}
