package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class X6 extends OA {
    public static final int zza = 1;
    public static final int zzb = 2;
    public static final int zzc = 3;
    private static final X6 zzd;
    private static volatile InterfaceC2219jB zze;
    private int zzf;
    private int zzg = 1000;
    private K6 zzh;
    private F6 zzi;

    static {
        X6 x6 = new X6();
        zzd = x6;
        OA.k(X6.class, x6);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zzd, "\u0004\u0003\u0000\u0001\u0001\u0003\u0003\u0000\u0000\u0000\u0001᠌\u0000\u0002ဉ\u0001\u0003ဉ\u0002", new Object[]{"zzf", "zzg", U3.t, "zzh", "zzi"});
        }
        if (iK == 3) {
            return new X6();
        }
        if (iK == 4) {
            return new W3(zzd);
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
        synchronized (X6.class) {
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
