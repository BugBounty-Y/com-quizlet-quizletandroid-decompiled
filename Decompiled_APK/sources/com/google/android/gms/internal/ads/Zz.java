package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class Zz extends OA {
    public static final /* synthetic */ int zza = 0;
    private static final Zz zzb;
    private static volatile InterfaceC2219jB zzc;
    private String zzd = "";
    private VA zze = C2348mB.e;

    static {
        Zz zz = new Zz();
        zzb = zz;
        OA.k(Zz.class, zz);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zzb, "\u0000\u0002\u0000\u0000\u0001\u0002\u0002\u0000\u0001\u0000\u0001Ȉ\u0002\u001b", new Object[]{"zzd", "zze", Hz.class});
        }
        if (iK == 3) {
            return new Zz();
        }
        if (iK == 4) {
            return new C1954d7(zzb);
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
        synchronized (Zz.class) {
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
