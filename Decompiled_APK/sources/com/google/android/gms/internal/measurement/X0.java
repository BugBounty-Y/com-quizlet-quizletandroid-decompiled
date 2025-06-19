package com.google.android.gms.internal.measurement;

import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class X0 extends W1 {
    private static final X0 zzb;
    private int zzd;
    private long zzg;
    private float zzh;
    private double zzi;
    private String zze = "";
    private String zzf = "";
    private InterfaceC2975c2 zzj = C3059t2.e;

    static {
        X0 x0 = new X0();
        zzb = x0;
        W1.j(X0.class, x0);
    }

    public static /* synthetic */ void A(X0 x0) {
        x0.zzd &= -3;
        x0.zzf = zzb.zzf;
    }

    public static /* synthetic */ void B(X0 x0, double d) {
        x0.zzd |= 16;
        x0.zzi = d;
    }

    public static /* synthetic */ void C(X0 x0, long j) {
        x0.zzd |= 4;
        x0.zzg = j;
    }

    public static /* synthetic */ void D(X0 x0, String str) {
        str.getClass();
        x0.zzd |= 1;
        x0.zze = str;
    }

    public static /* synthetic */ void E(X0 x0, String str) {
        str.getClass();
        x0.zzd |= 2;
        x0.zzf = str;
    }

    public static W0 r() {
        return (W0) zzb.e();
    }

    public static void v(X0 x0, ArrayList arrayList) {
        InterfaceC2975c2 interfaceC2975c2 = x0.zzj;
        if (!((K1) interfaceC2975c2).a) {
            int size = interfaceC2975c2.size();
            x0.zzj = interfaceC2975c2.f(size + size);
        }
        J1.b(arrayList, x0.zzj);
    }

    public static void w(X0 x0, X0 x02) {
        InterfaceC2975c2 interfaceC2975c2 = x0.zzj;
        if (!((K1) interfaceC2975c2).a) {
            int size = interfaceC2975c2.size();
            x0.zzj = interfaceC2975c2.f(size + size);
        }
        x0.zzj.add(x02);
    }

    public static /* synthetic */ void x(X0 x0) {
        x0.zzd &= -17;
        x0.zzi = 0.0d;
    }

    public static /* synthetic */ void y(X0 x0) {
        x0.zzd &= -5;
        x0.zzg = 0L;
    }

    public static void z(X0 x0) {
        x0.zzj = C3059t2.e;
    }

    public final boolean F() {
        return (this.zzd & 16) != 0;
    }

    public final boolean G() {
        return (this.zzd & 8) != 0;
    }

    public final boolean H() {
        return (this.zzd & 4) != 0;
    }

    public final boolean I() {
        return (this.zzd & 1) != 0;
    }

    public final boolean J() {
        return (this.zzd & 2) != 0;
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0006\u0000\u0001\u0001\u0006\u0006\u0000\u0001\u0000\u0001ဈ\u0000\u0002ဈ\u0001\u0003ဂ\u0002\u0004ခ\u0003\u0005က\u0004\u0006\u001b", new Object[]{"zzd", "zze", "zzf", "zzg", "zzh", "zzi", "zzj", X0.class});
        }
        if (i2 == 3) {
            return new X0();
        }
        if (i2 == 4) {
            return new W0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final double n() {
        return this.zzi;
    }

    public final float o() {
        return this.zzh;
    }

    public final int p() {
        return this.zzj.size();
    }

    public final long q() {
        return this.zzg;
    }

    public final String s() {
        return this.zze;
    }

    public final String t() {
        return this.zzf;
    }

    public final List u() {
        return this.zzj;
    }
}
