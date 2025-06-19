package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.ca, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1920ca extends androidx.appcompat.app.y {
    public final Object d;
    public final C1964da e;
    public boolean f;

    public C1920ca(C1964da c1964da) {
        super(6);
        this.d = new Object();
        this.e = c1964da;
    }

    public final void v() {
        com.google.android.gms.ads.internal.util.A.l("release: Trying to acquire lock");
        synchronized (this.d) {
            try {
                com.google.android.gms.ads.internal.util.A.l("release: Lock acquired");
                if (this.f) {
                    com.google.android.gms.ads.internal.util.A.l("release: Lock already released");
                    return;
                }
                this.f = true;
                u(new L9(3), new L9(20));
                u(new S4(this, 5), new C2881yn(this, 7));
                com.google.android.gms.ads.internal.util.A.l("release: Lock released");
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
