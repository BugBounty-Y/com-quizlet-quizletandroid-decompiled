package com.google.android.gms.internal.measurement;

/* renamed from: com.google.android.gms.internal.measurement.d1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2979d1 extends W1 {
    private static final C2979d1 zzb;
    private int zzd;
    private int zze = 1;
    private InterfaceC2975c2 zzf = C3059t2.e;

    static {
        C2979d1 c2979d1 = new C2979d1();
        zzb = c2979d1;
        W1.j(C2979d1.class, c2979d1);
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0001\u0000\u0001᠌\u0000\u0002\u001b", new Object[]{"zzd", "zze", C3047r0.h, "zzf", V0.class});
        }
        if (i2 == 3) {
            return new C2979d1();
        }
        if (i2 == 4) {
            return new C3043q0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }
}
