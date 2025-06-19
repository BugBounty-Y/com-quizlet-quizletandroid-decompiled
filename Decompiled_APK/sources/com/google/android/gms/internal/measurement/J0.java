package com.google.android.gms.internal.measurement;

/* loaded from: classes2.dex */
public final class J0 extends W1 {
    private static final J0 zzb;
    private int zzd;
    private int zzh;
    private String zze = "";
    private String zzf = "";
    private String zzg = "";
    private String zzi = "";

    static {
        J0 j0 = new J0();
        zzb = j0;
        W1.j(J0.class, j0);
    }

    public static J0 o() {
        return zzb;
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0005\u0000\u0001\u0001\u0005\u0005\u0000\u0000\u0000\u0001ဈ\u0000\u0002ဈ\u0001\u0003ဈ\u0002\u0004င\u0003\u0005ဈ\u0004", new Object[]{"zzd", "zze", "zzf", "zzg", "zzh", "zzi"});
        }
        if (i2 == 3) {
            return new J0();
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
        return this.zzh;
    }

    public final String p() {
        return this.zzf;
    }

    public final String q() {
        return this.zzi;
    }

    public final String r() {
        return this.zze;
    }
}
