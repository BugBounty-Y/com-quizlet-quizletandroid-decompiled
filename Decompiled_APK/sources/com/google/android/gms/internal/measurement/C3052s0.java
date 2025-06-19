package com.google.android.gms.internal.measurement;

/* renamed from: com.google.android.gms.internal.measurement.s0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3052s0 extends W1 {
    private static final C3052s0 zzb;
    private int zzd;
    private int zze;
    private boolean zzf;
    private String zzg = "";
    private String zzh = "";
    private String zzi = "";

    static {
        C3052s0 c3052s0 = new C3052s0();
        zzb = c3052s0;
        W1.j(C3052s0.class, c3052s0);
    }

    public static C3052s0 n() {
        return zzb;
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0005\u0000\u0001\u0001\u0005\u0005\u0000\u0000\u0000\u0001᠌\u0000\u0002ဇ\u0001\u0003ဈ\u0002\u0004ဈ\u0003\u0005ဈ\u0004", new Object[]{"zzd", "zze", C3047r0.b, "zzf", "zzg", "zzh", "zzi"});
        }
        if (i2 == 3) {
            return new C3052s0();
        }
        if (i2 == 4) {
            return new C3043q0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final String o() {
        return this.zzg;
    }

    public final String p() {
        return this.zzi;
    }

    public final String q() {
        return this.zzh;
    }

    public final boolean r() {
        return this.zzf;
    }

    public final boolean s() {
        return (this.zzd & 1) != 0;
    }

    public final boolean t() {
        return (this.zzd & 4) != 0;
    }

    public final boolean u() {
        return (this.zzd & 2) != 0;
    }

    public final boolean v() {
        return (this.zzd & 16) != 0;
    }

    public final boolean w() {
        return (this.zzd & 8) != 0;
    }

    public final int x() {
        int i;
        int i2 = this.zze;
        if (i2 != 0) {
            i = 2;
            if (i2 != 1) {
                if (i2 != 2) {
                    i = 4;
                    if (i2 != 3) {
                        i = i2 != 4 ? 0 : 5;
                    }
                } else {
                    i = 3;
                }
            }
        } else {
            i = 1;
        }
        if (i == 0) {
            return 1;
        }
        return i;
    }
}
