package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class S6 extends OA {
    public static final int zza = 1;
    public static final int zzb = 2;
    public static final int zzc = 3;
    private static final S6 zzd;
    private static volatile InterfaceC2219jB zze;
    private int zzf;
    private boolean zzg;
    private boolean zzh;
    private int zzi;

    static {
        S6 s6 = new S6();
        zzd = s6;
        OA.k(S6.class, s6);
    }

    public static void w(S6 s6, boolean z) {
        s6.zzf |= 1;
        s6.zzg = z;
    }

    public static void x(S6 s6, boolean z) {
        s6.zzf |= 2;
        s6.zzh = z;
    }

    public static void y(S6 s6, int i) {
        s6.zzf |= 4;
        s6.zzi = i;
    }

    public static R6 z() {
        return (R6) zzd.g();
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zzd, "\u0004\u0003\u0000\u0001\u0001\u0003\u0003\u0000\u0000\u0000\u0001ဇ\u0000\u0002ဇ\u0001\u0003ဋ\u0002", new Object[]{"zzf", "zzg", "zzh", "zzi"});
        }
        if (iK == 3) {
            return new S6();
        }
        if (iK == 4) {
            return new R6(zzd);
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
        synchronized (S6.class) {
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
