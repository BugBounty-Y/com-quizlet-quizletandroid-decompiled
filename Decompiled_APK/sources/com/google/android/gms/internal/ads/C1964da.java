package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.da, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1964da extends androidx.appcompat.app.y {
    public final Object d;
    public boolean e;
    public int f;

    public C1964da() {
        super(6);
        this.d = new Object();
        this.e = false;
        this.f = 0;
    }

    public final C1920ca v() {
        C1920ca c1920ca = new C1920ca(this);
        com.google.android.gms.ads.internal.util.A.l("createNewReference: Trying to acquire lock");
        synchronized (this.d) {
            com.google.android.gms.ads.internal.util.A.l("createNewReference: Lock acquired");
            u(new Os(c1920ca, 9), new Ts(c1920ca, 9));
            com.google.android.gms.common.internal.u.k(this.f >= 0);
            this.f++;
        }
        com.google.android.gms.ads.internal.util.A.l("createNewReference: Lock released");
        return c1920ca;
    }

    public final void w() {
        com.google.android.gms.ads.internal.util.A.l("markAsDestroyable: Trying to acquire lock");
        synchronized (this.d) {
            com.google.android.gms.ads.internal.util.A.l("markAsDestroyable: Lock acquired");
            com.google.android.gms.common.internal.u.k(this.f >= 0);
            com.google.android.gms.ads.internal.util.A.l("Releasing root reference. JS Engine will be destroyed once other references are released.");
            this.e = true;
            x();
        }
        com.google.android.gms.ads.internal.util.A.l("markAsDestroyable: Lock released");
    }

    public final void x() {
        com.google.android.gms.ads.internal.util.A.l("maybeDestroy: Trying to acquire lock");
        synchronized (this.d) {
            try {
                com.google.android.gms.ads.internal.util.A.l("maybeDestroy: Lock acquired");
                com.google.android.gms.common.internal.u.k(this.f >= 0);
                if (this.e && this.f == 0) {
                    com.google.android.gms.ads.internal.util.A.l("No reference is left (including root). Cleaning up engine.");
                    u(new L9(4), new L9(20));
                } else {
                    com.google.android.gms.ads.internal.util.A.l("There are still references to the engine. Not destroying.");
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        com.google.android.gms.ads.internal.util.A.l("maybeDestroy: Lock released");
    }

    public final void y() {
        com.google.android.gms.ads.internal.util.A.l("releaseOneReference: Trying to acquire lock");
        synchronized (this.d) {
            com.google.android.gms.ads.internal.util.A.l("releaseOneReference: Lock acquired");
            com.google.android.gms.common.internal.u.k(this.f > 0);
            com.google.android.gms.ads.internal.util.A.l("Releasing 1 reference for JS Engine");
            this.f--;
            x();
        }
        com.google.android.gms.ads.internal.util.A.l("releaseOneReference: Lock released");
    }
}
