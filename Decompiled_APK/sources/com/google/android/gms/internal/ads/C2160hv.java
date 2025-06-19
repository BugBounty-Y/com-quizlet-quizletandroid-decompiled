package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.hv, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2160hv {
    public static final C2160hv c;
    public static final C2160hv d;
    public final boolean a;
    public final RuntimeException b;

    static {
        if (AbstractC2674tv.f) {
            d = null;
            c = null;
        } else {
            d = new C2160hv(false, null);
            c = new C2160hv(true, null);
        }
    }

    public C2160hv(boolean z, RuntimeException runtimeException) {
        this.a = z;
        this.b = runtimeException;
    }
}
