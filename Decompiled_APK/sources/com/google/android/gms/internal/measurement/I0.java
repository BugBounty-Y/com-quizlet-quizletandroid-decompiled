package com.google.android.gms.internal.measurement;

/* loaded from: classes2.dex */
public final class I0 extends W1 {
    private static final I0 zzb;
    private int zzd;
    private String zze = "";
    private String zzf = "";

    static {
        I0 i0 = new I0();
        zzb = i0;
        W1.j(I0.class, i0);
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0000\u0000\u0001ဈ\u0000\u0002ဈ\u0001", new Object[]{"zzd", "zze", "zzf"});
        }
        if (i2 == 3) {
            return new I0();
        }
        if (i2 == 4) {
            return new C3043q0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final String n() {
        return this.zze;
    }

    public final String o() {
        return this.zzf;
    }
}
