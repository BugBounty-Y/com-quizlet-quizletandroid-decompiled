package com.google.android.gms.internal.measurement;

/* renamed from: com.google.android.gms.internal.measurement.m1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3024m1 extends W1 {
    private static final C3024m1 zzb;
    private InterfaceC2975c2 zzd = C3059t2.e;

    static {
        C3024m1 c3024m1 = new C3024m1();
        zzb = c3024m1;
        W1.j(C3024m1.class, c3024m1);
    }

    public static C3024m1 o() {
        return zzb;
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0001\u0000\u0000\u0001\u0001\u0001\u0000\u0001\u0000\u0001\u001b", new Object[]{"zzd", C3029n1.class});
        }
        if (i2 == 3) {
            return new C3024m1();
        }
        if (i2 == 4) {
            return new C3043q0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final int n() {
        return this.zzd.size();
    }

    public final InterfaceC2975c2 p() {
        return this.zzd;
    }
}
