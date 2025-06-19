package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class L6 extends OA {
    public static final int zza = 1;
    public static final int zzb = 2;
    public static final int zzc = 3;
    public static final int zzd = 4;
    private static final L6 zze;
    private static volatile InterfaceC2219jB zzf;
    private int zzg;
    private H6 zzh;
    private int zzi = 1000;
    private K6 zzj;
    private F6 zzk;

    static {
        L6 l6 = new L6();
        zze = l6;
        OA.k(L6.class, l6);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zze, "\u0004\u0004\u0000\u0001\u0001\u0004\u0004\u0000\u0000\u0000\u0001ဉ\u0000\u0002᠌\u0001\u0003ဉ\u0002\u0004ဉ\u0003", new Object[]{"zzg", "zzh", "zzi", U3.t, "zzj", "zzk"});
        }
        if (iK == 3) {
            return new L6();
        }
        if (iK == 4) {
            return new W3(zze);
        }
        if (iK == 5) {
            return zze;
        }
        if (iK != 6) {
            throw null;
        }
        InterfaceC2219jB interfaceC2219jB = zzf;
        if (interfaceC2219jB != null) {
            return interfaceC2219jB;
        }
        synchronized (L6.class) {
            try {
                na = zzf;
                if (na == null) {
                    na = new NA();
                    zzf = na;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return na;
    }
}
