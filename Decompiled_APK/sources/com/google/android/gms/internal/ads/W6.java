package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class W6 extends OA {
    public static final int zza = 1;
    public static final int zzb = 2;
    public static final int zzc = 3;
    public static final int zzd = 4;
    public static final int zze = 5;
    public static final int zzf = 6;
    private static final W6 zzg;
    private static volatile InterfaceC2219jB zzh;
    private int zzi;
    private int zzj = 1000;
    private K6 zzk;
    private int zzl;
    private int zzm;
    private int zzn;
    private long zzo;

    static {
        W6 w6 = new W6();
        zzg = w6;
        OA.k(W6.class, w6);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zzg, "\u0004\u0006\u0000\u0001\u0001\u0006\u0006\u0000\u0000\u0000\u0001᠌\u0000\u0002ဉ\u0001\u0003င\u0002\u0004င\u0003\u0005င\u0004\u0006ဃ\u0005", new Object[]{"zzi", "zzj", U3.t, "zzk", "zzl", "zzm", "zzn", "zzo"});
        }
        if (iK == 3) {
            return new W6();
        }
        if (iK == 4) {
            return new W3(zzg);
        }
        if (iK == 5) {
            return zzg;
        }
        if (iK != 6) {
            throw null;
        }
        InterfaceC2219jB interfaceC2219jB = zzh;
        if (interfaceC2219jB != null) {
            return interfaceC2219jB;
        }
        synchronized (W6.class) {
            try {
                na = zzh;
                if (na == null) {
                    na = new NA();
                    zzh = na;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return na;
    }
}
