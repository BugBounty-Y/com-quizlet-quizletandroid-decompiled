package com.google.android.gms.internal.measurement;

/* loaded from: classes2.dex */
public final class C0 extends W1 {
    private static final C0 zzb;
    private int zzd;
    private String zze = "";
    private boolean zzf;
    private boolean zzg;
    private int zzh;

    static {
        C0 c0 = new C0();
        zzb = c0;
        W1.j(C0.class, c0);
    }

    public static /* synthetic */ void p(C0 c0, String str) {
        str.getClass();
        c0.zzd |= 1;
        c0.zze = str;
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0004\u0000\u0001\u0001\u0004\u0004\u0000\u0000\u0000\u0001ဈ\u0000\u0002ဇ\u0001\u0003ဇ\u0002\u0004င\u0003", new Object[]{"zzd", "zze", "zzf", "zzg", "zzh"});
        }
        if (i2 == 3) {
            return new C0();
        }
        if (i2 == 4) {
            return new B0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final int n() {
        return this.zzh;
    }

    public final String o() {
        return this.zze;
    }

    public final boolean q() {
        return this.zzf;
    }

    public final boolean r() {
        return this.zzg;
    }

    public final boolean s() {
        return (this.zzd & 2) != 0;
    }

    public final boolean t() {
        return (this.zzd & 4) != 0;
    }

    public final boolean u() {
        return (this.zzd & 8) != 0;
    }
}
