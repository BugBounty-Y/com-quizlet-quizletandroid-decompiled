package com.google.android.gms.internal.measurement;

/* loaded from: classes2.dex */
public final class Y0 extends W1 {
    private static final Y0 zzb;
    private int zzd;
    private String zze = "";
    private String zzf = "";
    private M0 zzg;

    static {
        Y0 y0 = new Y0();
        zzb = y0;
        W1.j(Y0.class, y0);
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0003\u0000\u0001\u0001\u0003\u0003\u0000\u0000\u0000\u0001ဈ\u0000\u0002ဈ\u0001\u0003ဉ\u0002", new Object[]{"zzd", "zze", "zzf", "zzg"});
        }
        if (i2 == 3) {
            return new Y0();
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
