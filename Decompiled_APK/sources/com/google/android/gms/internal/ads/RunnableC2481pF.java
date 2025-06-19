package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.pF, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC2481pF implements Runnable {
    public final /* synthetic */ int a;
    public final C2695uF b;

    public /* synthetic */ RunnableC2481pF(C2695uF c2695uF, int i) {
        this.a = i;
        this.b = c2695uF;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.F = true;
                break;
            case 1:
                this.b.w();
                break;
            case 2:
                C2695uF c2695uF = this.b;
                if (!c2695uF.L) {
                    InterfaceC1962dF interfaceC1962dF = c2695uF.o;
                    interfaceC1962dF.getClass();
                    interfaceC1962dF.g(c2695uF);
                    break;
                }
                break;
            default:
                C2695uF c2695uF2 = this.b;
                for (C2910zF c2910zF : c2695uF2.q) {
                    c2910zF.m(true);
                    if (c2910zF.A != null) {
                        c2910zF.A = null;
                        c2910zF.f = null;
                    }
                }
                Iw iw = c2695uF2.j;
                if (((U) iw.a) != null) {
                    iw.a = null;
                }
                iw.b = null;
                break;
        }
    }
}
