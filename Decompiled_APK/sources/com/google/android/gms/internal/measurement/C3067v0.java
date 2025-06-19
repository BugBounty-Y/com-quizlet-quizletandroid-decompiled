package com.google.android.gms.internal.measurement;

/* renamed from: com.google.android.gms.internal.measurement.v0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3067v0 extends W1 {
    private static final C3067v0 zzb;
    private int zzd;
    private int zze;
    private boolean zzg;
    private String zzf = "";
    private InterfaceC2975c2 zzh = C3059t2.e;

    static {
        C3067v0 c3067v0 = new C3067v0();
        zzb = c3067v0;
        W1.j(C3067v0.class, c3067v0);
    }

    public static C3067v0 o() {
        return zzb;
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0004\u0000\u0001\u0001\u0004\u0004\u0000\u0001\u0000\u0001᠌\u0000\u0002ဈ\u0001\u0003ဇ\u0002\u0004\u001a", new Object[]{"zzd", "zze", C3047r0.c, "zzf", "zzg", "zzh"});
        }
        if (i2 == 3) {
            return new C3067v0();
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
        return this.zzh.size();
    }

    public final String p() {
        return this.zzf;
    }

    public final InterfaceC2975c2 q() {
        return this.zzh;
    }

    public final boolean r() {
        return this.zzg;
    }

    public final boolean s() {
        return (this.zzd & 4) != 0;
    }

    public final boolean t() {
        return (this.zzd & 2) != 0;
    }

    public final boolean u() {
        return (this.zzd & 1) != 0;
    }

    public final int v() {
        int i;
        switch (this.zze) {
            case 0:
                i = 1;
                break;
            case 1:
                i = 2;
                break;
            case 2:
                i = 3;
                break;
            case 3:
                i = 4;
                break;
            case 4:
                i = 5;
                break;
            case 5:
                i = 6;
                break;
            case 6:
                i = 7;
                break;
            default:
                i = 0;
                break;
        }
        if (i == 0) {
            return 1;
        }
        return i;
    }
}
