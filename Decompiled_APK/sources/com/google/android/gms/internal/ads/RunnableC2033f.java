package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.f, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC2033f implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ C1732Mb b;

    public /* synthetic */ RunnableC2033f(C1732Mb c1732Mb, int i) {
        this.a = i;
        this.b = c1732Mb;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                ((C2077g) this.b.c).h.mo11zza();
                break;
            case 1:
                ((C2077g) this.b.c).h.a();
                break;
            default:
                ((C2077g) this.b.c).h.getClass();
                break;
        }
    }

    public /* synthetic */ RunnableC2033f(C1732Mb c1732Mb, C1740Nd c1740Nd) {
        this.a = 2;
        this.b = c1732Mb;
    }
}
