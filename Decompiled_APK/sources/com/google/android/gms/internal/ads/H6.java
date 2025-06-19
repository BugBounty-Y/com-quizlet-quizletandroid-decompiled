package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class H6 extends OA {
    public static final int zza = 1;
    public static final int zzb = 2;
    public static final int zzc = 3;
    private static final H6 zzd;
    private static volatile InterfaceC2219jB zze;
    private int zzf;
    private int zzg;
    private int zzh;
    private int zzi;

    static {
        H6 h6 = new H6();
        zzd = h6;
        OA.k(H6.class, h6);
    }

    public static void w(H6 h6, int i) {
        h6.zzf |= 1;
        h6.zzg = i;
    }

    public static void x(H6 h6, int i) {
        h6.zzf |= 4;
        h6.zzi = i;
    }

    public static void y(H6 h6, int i) {
        h6.zzf |= 2;
        h6.zzh = i;
    }

    public static G6 z() {
        return (G6) zzd.g();
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zzd, "\u0004\u0003\u0000\u0001\u0001\u0003\u0003\u0000\u0000\u0000\u0001င\u0000\u0002င\u0001\u0003င\u0002", new Object[]{"zzf", "zzg", "zzh", "zzi"});
        }
        if (iK == 3) {
            return new H6();
        }
        if (iK == 4) {
            return new G6(zzd);
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
        synchronized (H6.class) {
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
