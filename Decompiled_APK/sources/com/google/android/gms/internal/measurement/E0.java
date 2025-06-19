package com.google.android.gms.internal.measurement;

import java.util.List;

/* loaded from: classes2.dex */
public final class E0 extends W1 {
    private static final E0 zzb;
    private int zzd;
    private long zze;
    private String zzf = "";
    private int zzg;
    private InterfaceC2975c2 zzh;
    private InterfaceC2975c2 zzi;
    private InterfaceC2975c2 zzj;
    private String zzk;
    private boolean zzl;
    private InterfaceC2975c2 zzm;
    private InterfaceC2975c2 zzn;
    private String zzo;
    private String zzp;
    private C3087z0 zzq;
    private G0 zzr;
    private J0 zzs;
    private H0 zzt;
    private F0 zzu;

    static {
        E0 e0 = new E0();
        zzb = e0;
        W1.j(E0.class, e0);
    }

    public E0() {
        C3059t2 c3059t2 = C3059t2.e;
        this.zzh = c3059t2;
        this.zzi = c3059t2;
        this.zzj = c3059t2;
        this.zzk = "";
        this.zzm = c3059t2;
        this.zzn = c3059t2;
        this.zzo = "";
        this.zzp = "";
    }

    public static void B(E0 e0) {
        e0.zzj = C3059t2.e;
    }

    public static void C(E0 e0) {
        e0.zzm = C3059t2.e;
    }

    public static void D(E0 e0, int i, C0 c0) {
        InterfaceC2975c2 interfaceC2975c2 = e0.zzi;
        if (!((K1) interfaceC2975c2).a) {
            int size = interfaceC2975c2.size();
            e0.zzi = interfaceC2975c2.f(size + size);
        }
        e0.zzi.set(i, c0);
    }

    public static D0 s() {
        return (D0) zzb.e();
    }

    public static E0 t() {
        return zzb;
    }

    public final List A() {
        return this.zzh;
    }

    public final boolean E() {
        return (this.zzd & 128) != 0;
    }

    public final boolean F() {
        return (this.zzd & 2) != 0;
    }

    public final boolean G() {
        return (this.zzd & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0;
    }

    public final boolean H() {
        return (this.zzd & 1) != 0;
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0011\u0000\u0001\u0001\u0013\u0011\u0000\u0005\u0000\u0001ဂ\u0000\u0002ဈ\u0001\u0003င\u0002\u0004\u001b\u0005\u001b\u0006\u001b\u0007ဈ\u0003\bဇ\u0004\t\u001b\n\u001b\u000bဈ\u0005\u000eဈ\u0006\u000fဉ\u0007\u0010ဉ\b\u0011ဉ\t\u0012ဉ\n\u0013ဉ\u000b", new Object[]{"zzd", "zze", "zzf", "zzg", "zzh", I0.class, "zzi", C0.class, "zzj", C3018l0.class, "zzk", "zzl", "zzm", C3034o1.class, "zzn", A0.class, "zzo", "zzp", "zzq", "zzr", "zzs", "zzt", "zzu"});
        }
        if (i2 == 3) {
            return new E0();
        }
        if (i2 == 4) {
            return new D0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final int n() {
        return this.zzm.size();
    }

    public final int o() {
        return this.zzi.size();
    }

    public final long p() {
        return this.zze;
    }

    public final C3087z0 q() {
        C3087z0 c3087z0 = this.zzq;
        return c3087z0 == null ? C3087z0.n() : c3087z0;
    }

    public final C0 r(int i) {
        return (C0) this.zzi.get(i);
    }

    public final J0 u() {
        J0 j0 = this.zzs;
        return j0 == null ? J0.o() : j0;
    }

    public final String v() {
        return this.zzf;
    }

    public final String w() {
        return this.zzo;
    }

    public final InterfaceC2975c2 x() {
        return this.zzj;
    }

    public final InterfaceC2975c2 y() {
        return this.zzn;
    }

    public final InterfaceC2975c2 z() {
        return this.zzm;
    }
}
