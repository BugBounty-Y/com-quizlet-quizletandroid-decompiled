package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.c7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1910c7 extends OA {
    public static final int zza = 1;
    public static final int zzb = 2;
    private static final C1910c7 zzc;
    private static volatile InterfaceC2219jB zzd;
    private int zze;
    private int zzf;
    private D6 zzg;

    static {
        C1910c7 c1910c7 = new C1910c7();
        zzc = c1910c7;
        OA.k(C1910c7.class, c1910c7);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zzc, "\u0004\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0000\u0000\u0001᠌\u0000\u0002ဉ\u0001", new Object[]{"zze", "zzf", U3.r, "zzg"});
        }
        if (iK == 3) {
            return new C1910c7();
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
        synchronized (C1910c7.class) {
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
