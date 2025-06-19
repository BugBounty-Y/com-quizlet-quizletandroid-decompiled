package com.google.android.gms.internal.measurement;

import java.util.List;

/* renamed from: com.google.android.gms.internal.measurement.z0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3087z0 extends W1 {
    private static final C3087z0 zzb;
    private int zzd;
    private InterfaceC2975c2 zze;
    private InterfaceC2975c2 zzf;
    private InterfaceC2975c2 zzg;
    private boolean zzh;
    private InterfaceC2975c2 zzi;

    static {
        C3087z0 c3087z0 = new C3087z0();
        zzb = c3087z0;
        W1.j(C3087z0.class, c3087z0);
    }

    public C3087z0() {
        C3059t2 c3059t2 = C3059t2.e;
        this.zze = c3059t2;
        this.zzf = c3059t2;
        this.zzg = c3059t2;
        this.zzi = c3059t2;
    }

    public static C3087z0 n() {
        return zzb;
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0005\u0000\u0001\u0001\u0005\u0005\u0000\u0004\u0000\u0001\u001b\u0002\u001b\u0003\u001b\u0004ဇ\u0000\u0005\u001b", new Object[]{"zzd", "zze", C3072w0.class, "zzf", C3077x0.class, "zzg", C3082y0.class, "zzh", "zzi", C3072w0.class});
        }
        if (i2 == 3) {
            return new C3087z0();
        }
        if (i2 == 4) {
            return new C3043q0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final InterfaceC2975c2 o() {
        return this.zzg;
    }

    public final InterfaceC2975c2 p() {
        return this.zze;
    }

    public final InterfaceC2975c2 q() {
        return this.zzf;
    }

    public final List r() {
        return this.zzi;
    }

    public final boolean s() {
        return this.zzh;
    }

    public final boolean t() {
        return (this.zzd & 1) != 0;
    }
}
