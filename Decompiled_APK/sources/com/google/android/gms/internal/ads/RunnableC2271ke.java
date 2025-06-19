package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.ke, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC2271ke implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ C2314le b;

    public /* synthetic */ RunnableC2271ke(C2314le c2314le, int i) {
        this.a = i;
        this.b = c2314le;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                C2785wd c2785wd = this.b.e;
                if (c2785wd != null) {
                    c2785wd.g();
                    break;
                }
                break;
            case 1:
                C2314le c2314le = this.b;
                C2785wd c2785wd2 = c2314le.e;
                if (c2785wd2 != null) {
                    if (!c2314le.f) {
                        c2785wd2.h();
                        c2314le.f = true;
                    }
                    c2314le.e.f();
                    break;
                }
                break;
            default:
                C2785wd c2785wd3 = this.b.e;
                if (c2785wd3 != null) {
                    c2785wd3.e();
                    break;
                }
                break;
        }
    }
}
