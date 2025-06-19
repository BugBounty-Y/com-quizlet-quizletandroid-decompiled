package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.v6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2729v6 extends OA {
    public static final int zza = 1;
    public static final int zzb = 2;
    private static final C2729v6 zzc;
    private static volatile InterfaceC2219jB zzd;
    private int zze;
    private int zzf;
    private F6 zzg;

    static {
        C2729v6 c2729v6 = new C2729v6();
        zzc = c2729v6;
        OA.k(C2729v6.class, c2729v6);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zzc, "\u0004\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0000\u0000\u0001᠌\u0000\u0002ဉ\u0001", new Object[]{"zze", "zzf", U3.t, "zzg"});
        }
        if (iK == 3) {
            return new C2729v6();
        }
        if (iK == 4) {
            return new W3(zzc);
        }
        if (iK == 5) {
            return zzc;
        }
        if (iK != 6) {
            throw null;
        }
        InterfaceC2219jB interfaceC2219jB = zzd;
        if (interfaceC2219jB != null) {
            return interfaceC2219jB;
        }
        synchronized (C2729v6.class) {
            try {
                na = zzd;
                if (na == null) {
                    na = new NA();
                    zzd = na;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return na;
    }
}
