package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.mq, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2369mq {
    public final InterfaceC2911za a;

    public C2369mq(InterfaceC2911za interfaceC2911za) {
        this.a = interfaceC2911za;
    }

    public final boolean a() throws zzfcw {
        try {
            return this.a.L();
        } catch (Throwable th) {
            throw new zzfcw(th);
        }
    }

    public final void b(boolean z) {
        try {
            this.a.J2(z);
        } catch (Throwable th) {
            throw new zzfcw(th);
        }
    }
}
