package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class U6 extends OA {
    public static final int zza = 1;
    public static final int zzb = 2;
    public static final int zzc = 3;
    public static final int zzd = 4;
    public static final int zze = 5;
    private static final U6 zzf;
    private static volatile InterfaceC2219jB zzg;
    private int zzh;
    private int zzi = 1000;
    private K6 zzj;
    private int zzk;
    private int zzl;
    private int zzm;

    static {
        U6 u6 = new U6();
        zzf = u6;
        OA.k(U6.class, u6);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zzf, "\u0004\u0005\u0000\u0001\u0001\u0005\u0005\u0000\u0000\u0000\u0001᠌\u0000\u0002ဉ\u0001\u0003င\u0002\u0004င\u0003\u0005င\u0004", new Object[]{"zzh", "zzi", U3.t, "zzj", "zzk", "zzl", "zzm"});
        }
        if (iK == 3) {
            return new U6();
        }
        if (iK == 4) {
            return new W3(zzf);
        }
        if (iK == 5) {
            return zzf;
        }
        if (iK != 6) {
            throw null;
        }
        InterfaceC2219jB interfaceC2219jB = zzg;
        if (interfaceC2219jB != null) {
            return interfaceC2219jB;
        }
        synchronized (U6.class) {
            try {
                na = zzg;
                if (na == null) {
                    na = new NA();
                    zzg = na;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return na;
    }
}
