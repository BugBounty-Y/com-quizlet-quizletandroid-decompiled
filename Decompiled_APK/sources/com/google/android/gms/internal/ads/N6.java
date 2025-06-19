package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class N6 extends OA {
    public static final int zza = 1;
    public static final int zzb = 2;
    public static final int zzc = 3;
    private static final N6 zzd;
    private static volatile InterfaceC2219jB zze;
    private int zzf;
    private int zzg;
    private Q6 zzh;
    private S6 zzi;

    static {
        N6 n6 = new N6();
        zzd = n6;
        OA.k(N6.class, n6);
    }

    public static void w(N6 n6) {
        n6.getClass();
        n6.zzg = AbstractC0147y.k(2);
        n6.zzf |= 1;
    }

    public static void x(N6 n6, Q6 q6) {
        n6.getClass();
        q6.getClass();
        n6.zzh = q6;
        n6.zzf |= 2;
    }

    public static void y(N6 n6, S6 s6) {
        n6.getClass();
        n6.zzi = s6;
        n6.zzf |= 4;
    }

    public static M6 z() {
        return (M6) zzd.g();
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zzd, "\u0004\u0003\u0000\u0001\u0001\u0003\u0003\u0000\u0000\u0000\u0001᠌\u0000\u0002ဉ\u0001\u0003ဉ\u0002", new Object[]{"zzf", "zzg", U3.q, "zzh", "zzi"});
        }
        if (iK == 3) {
            return new N6();
        }
        if (iK == 4) {
            return new M6(zzd);
        }
        if (iK == 5) {
            return zzd;
        }
        if (iK != 6) {
            throw null;
        }
        InterfaceC2219jB interfaceC2219jB = zze;
        if (interfaceC2219jB != null) {
            return interfaceC2219jB;
        }
        synchronized (N6.class) {
            try {
                na = zze;
                if (na == null) {
                    na = new NA();
                    zze = na;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return na;
    }
}
