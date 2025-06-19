package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class Zq extends OA {
    private static final Zq zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private Wq zzd;

    static {
        Zq zq = new Zq();
        zza = zq;
        OA.k(Zq.class, zq);
    }

    public static Yq w() {
        return (Yq) zza.g();
    }

    public static /* synthetic */ void x(Zq zq, Wq wq) {
        zq.zzd = wq;
        zq.zzc |= 1;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0004\u0001\u0000\u0001\u0006\u0006\u0001\u0000\u0000\u0000\u0006ဉ\u0000", new Object[]{"zzc", "zzd"});
        }
        if (iK == 3) {
            return new Zq();
        }
        if (iK == 4) {
            return new Yq(zza);
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
        synchronized (Zq.class) {
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
