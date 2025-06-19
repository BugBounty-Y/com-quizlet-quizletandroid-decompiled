package com.google.android.gms.internal.measurement;

/* renamed from: com.google.android.gms.internal.measurement.p1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3039p1 extends W1 {
    private static final C3039p1 zzb;
    private int zzd;
    private int zze;
    private InterfaceC2975c2 zzf = C3059t2.e;
    private String zzg = "";
    private String zzh = "";
    private boolean zzi;
    private double zzj;

    static {
        C3039p1 c3039p1 = new C3039p1();
        zzb = c3039p1;
        W1.j(C3039p1.class, c3039p1);
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0006\u0000\u0001\u0001\u0006\u0006\u0000\u0001\u0000\u0001᠌\u0000\u0002\u001b\u0003ဈ\u0001\u0004ဈ\u0002\u0005ဇ\u0003\u0006က\u0004", new Object[]{"zzd", "zze", C3047r0.l, "zzf", C3039p1.class, "zzg", "zzh", "zzi", "zzj"});
        }
        if (i2 == 3) {
            return new C3039p1();
        }
        if (i2 == 4) {
            return new C3043q0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final double n() {
        return this.zzj;
    }

    public final String o() {
        return this.zzg;
    }

    public final String p() {
        return this.zzh;
    }

    public final InterfaceC2975c2 q() {
        return this.zzf;
    }

    public final boolean r() {
        return this.zzi;
    }

    public final boolean s() {
        return (this.zzd & 8) != 0;
    }

    public final boolean t() {
        return (this.zzd & 16) != 0;
    }

    public final boolean u() {
        return (this.zzd & 4) != 0;
    }

    public final int v() {
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
