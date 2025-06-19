package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class K6 extends OA {
    public static final int zza = 1;
    private static final K6 zzb;
    private static volatile InterfaceC2219jB zzc;
    private int zzd;
    private int zze;

    static {
        K6 k6 = new K6();
        zzb = k6;
        OA.k(K6.class, k6);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zzb, "\u0004\u0001\u0000\u0001\u0001\u0001\u0001\u0000\u0000\u0000\u0001᠌\u0000", new Object[]{"zzd", "zze", U3.p});
        }
        if (iK == 3) {
            return new K6();
        }
        if (iK == 4) {
            return new W3(zzb);
        }
        if (iK == 5) {
            return zzb;
        }
        if (iK != 6) {
            throw null;
        }
        InterfaceC2219jB interfaceC2219jB = zzc;
        if (interfaceC2219jB != null) {
            return interfaceC2219jB;
        }
        synchronized (K6.class) {
            try {
                na = zzc;
                if (na == null) {
                    na = new NA();
                    zzc = na;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return na;
    }
}
