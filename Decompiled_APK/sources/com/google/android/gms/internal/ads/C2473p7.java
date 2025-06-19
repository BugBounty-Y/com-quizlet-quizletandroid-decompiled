package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.p7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2473p7 extends OA {
    public static final int zza = 1;
    public static final int zzb = 2;
    public static final int zzc = 3;
    public static final int zzd = 4;
    private static final C2473p7 zze;
    private static volatile InterfaceC2219jB zzf;
    private int zzg;
    private C2387n7 zzh;
    private VA zzi = C2348mB.e;
    private int zzj;
    private F6 zzk;

    static {
        C2473p7 c2473p7 = new C2473p7();
        zze = c2473p7;
        OA.k(C2473p7.class, c2473p7);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zze, "\u0004\u0004\u0000\u0001\u0001\u0004\u0004\u0000\u0001\u0000\u0001ဉ\u0000\u0002\u001b\u0003᠌\u0001\u0004ဉ\u0002", new Object[]{"zzg", "zzh", "zzi", E6.class, "zzj", U3.t, "zzk"});
        }
        if (iK == 3) {
            return new C2473p7();
        }
        if (iK == 4) {
            return new C1954d7(zze);
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
        synchronized (C2473p7.class) {
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
