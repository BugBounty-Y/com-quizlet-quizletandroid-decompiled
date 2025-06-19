package com.google.android.gms.internal.measurement;

/* loaded from: classes2.dex */
public final class V0 extends W1 {
    private static final V0 zzb;
    private int zzd;
    private String zze = "";
    private long zzf;

    static {
        V0 v0 = new V0();
        zzb = v0;
        W1.j(V0.class, v0);
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0000\u0000\u0001ဈ\u0000\u0002ဂ\u0001", new Object[]{"zzd", "zze", "zzf"});
        }
        if (i2 == 3) {
            return new V0();
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
