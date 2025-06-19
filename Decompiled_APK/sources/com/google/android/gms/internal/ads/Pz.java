package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class Pz extends OA {
    private static final Pz zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private VA zzd = C2348mB.e;

    static {
        Pz pz = new Pz();
        zza = pz;
        OA.k(Pz.class, pz);
    }

    public static Mz w() {
        return (Mz) zza.g();
    }

    public static void x(Pz pz, Oz oz) {
        VA va = pz.zzd;
        if (!((AbstractC2690uA) va).a) {
            int size = va.size();
            pz.zzd = va.d(size + size);
        }
        pz.zzd.add(oz);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0002\u0000\u0000\u0001\u0002\u0002\u0000\u0001\u0000\u0001\u000b\u0002\u001b", new Object[]{"zzc", "zzd", Oz.class});
        }
        if (iK == 3) {
            return new Pz();
        }
        if (iK == 4) {
            return new Mz(zza);
        }
        if (iK == 5) {
            return zza;
        }
        if (iK != 6) {
            throw null;
        }
        InterfaceC2219jB interfaceC2219jB = zzb;
        if (interfaceC2219jB != null) {
            return interfaceC2219jB;
        }
        synchronized (Pz.class) {
            try {
                na = zzb;
                if (na == null) {
                    na = new NA();
                    zzb = na;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return na;
    }
}
