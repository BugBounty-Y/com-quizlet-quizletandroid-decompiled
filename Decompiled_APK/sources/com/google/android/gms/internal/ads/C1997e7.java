package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.e7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1997e7 extends OA {
    public static final int zza = 1;
    public static final int zzb = 2;
    public static final int zzc = 3;
    private static final C1997e7 zzd;
    private static volatile InterfaceC2219jB zze;
    private int zzf;
    private String zzg = "";
    private VA zzh = C2348mB.e;
    private int zzi;

    static {
        C1997e7 c1997e7 = new C1997e7();
        zzd = c1997e7;
        OA.k(C1997e7.class, c1997e7);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zzd, "\u0004\u0003\u0000\u0001\u0001\u0003\u0003\u0000\u0001\u0000\u0001ဈ\u0000\u0002\u001b\u0003᠌\u0001", new Object[]{"zzf", "zzg", "zzh", C1910c7.class, "zzi", U3.t});
        }
        if (iK == 3) {
            return new C1997e7();
        }
        if (iK == 4) {
            return new C1954d7(zzd);
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
        synchronized (C1997e7.class) {
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
