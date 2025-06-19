package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.v5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2728v5 extends OA {
    private static final C2728v5 zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private String zzd = "";
    private String zze = "";
    private long zzf;
    private long zzg;
    private long zzh;

    static {
        C2728v5 c2728v5 = new C2728v5();
        zza = c2728v5;
        OA.k(C2728v5.class, c2728v5);
    }

    public static C2728v5 A() {
        return zza;
    }

    public static C2728v5 B(C2905zA c2905zA) {
        C2728v5 c2728v5 = zza;
        IA ia = IA.a;
        C2305lB c2305lB = C2305lB.c;
        OA oaO = OA.o(c2728v5, c2905zA, IA.b);
        OA.t(oaO);
        return (C2728v5) oaO;
    }

    public static C2728v5 C(C2905zA c2905zA, IA ia) {
        return (C2728v5) OA.o(zza, c2905zA, ia);
    }

    public static /* synthetic */ void F(C2728v5 c2728v5, String str) {
        str.getClass();
        c2728v5.zzc |= 2;
        c2728v5.zze = str;
    }

    public static /* synthetic */ void G(C2728v5 c2728v5, long j) {
        c2728v5.zzc |= 8;
        c2728v5.zzg = j;
    }

    public static /* synthetic */ void H(C2728v5 c2728v5, long j) {
        c2728v5.zzc |= 4;
        c2728v5.zzf = j;
    }

    public static /* synthetic */ void I(C2728v5 c2728v5, long j) {
        c2728v5.zzc |= 16;
        c2728v5.zzh = j;
    }

    public static /* synthetic */ void J(C2728v5 c2728v5, String str) {
        str.getClass();
        c2728v5.zzc |= 1;
        c2728v5.zzd = str;
    }

    public static C2685u5 z() {
        return (C2685u5) zza.g();
    }

    public final String D() {
        return this.zze;
    }

    public final String E() {
        return this.zzd;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0004\u0005\u0000\u0001\u0001\u0005\u0005\u0000\u0000\u0000\u0001ဈ\u0000\u0002ဈ\u0001\u0003ဃ\u0002\u0004ဃ\u0003\u0005ဃ\u0004", new Object[]{"zzc", "zzd", "zze", "zzf", "zzg", "zzh"});
        }
        if (iK == 3) {
            return new C2728v5();
        }
        if (iK == 4) {
            return new C2685u5(zza);
        }
        if (iK == 5) {
            return zza;
        }
        if (iK != 6) {
            throw null;
        }
        InterfaceC2219jB interfaceC2219jB = zzb;
        if (interfaceC2219jB != null) {
            return interfaceC2219jB;
        }
        synchronized (C2728v5.class) {
            try {
                na = zzb;
                if (na == null) {
                    na = new NA();
                    zzb = na;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return na;
    }

    public final long w() {
        return this.zzg;
    }

    public final long x() {
        return this.zzf;
    }

    public final long y() {
        return this.zzh;
    }
}
