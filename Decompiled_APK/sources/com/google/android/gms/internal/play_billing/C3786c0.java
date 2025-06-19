package com.google.android.gms.internal.play_billing;

/* renamed from: com.google.android.gms.internal.play_billing.c0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3786c0 {
    public static final C3786c0 c;
    public static final C3786c0 d;
    public final boolean a;
    public final RuntimeException b;

    static {
        if (AbstractC3816m0.d) {
            d = null;
            c = null;
        } else {
            d = new C3786c0(false, null);
            c = new C3786c0(true, null);
        }
    }

    public C3786c0(boolean z, RuntimeException runtimeException) {
        this.a = z;
        this.b = runtimeException;
    }
}
