package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.a4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1820a4 extends OA {
    public static final /* synthetic */ int zza = 0;
    private static final C1820a4 zzb;
    private static volatile InterfaceC2219jB zzc;
    private int zzd;
    private boolean zzf;
    private boolean zzg;
    private long zze = 100;
    private long zzh = 300;
    private long zzi = 1000;

    static {
        C1820a4 c1820a4 = new C1820a4();
        zzb = c1820a4;
        OA.k(C1820a4.class, c1820a4);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zzb, "\u0004\u0005\u0000\u0001\u0001\u0005\u0005\u0000\u0000\u0000\u0001ဂ\u0000\u0002ဇ\u0001\u0003ဇ\u0002\u0004ဂ\u0003\u0005ဂ\u0004", new Object[]{"zzd", "zze", "zzf", "zzg", "zzh", "zzi"});
        }
        if (iK == 3) {
            return new C1820a4();
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
        synchronized (C1820a4.class) {
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
