package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class MB extends OA {
    private static final MB zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private String zzd = "";

    static {
        MB mb = new MB();
        zza = mb;
        OA.k(MB.class, mb);
    }

    public static LB w() {
        return (LB) zza.g();
    }

    public static /* synthetic */ void x(MB mb, String str) {
        mb.zzc |= 1;
        mb.zzd = str;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0001\u0001\u0000\u0001\u0001\u0001\u0001\u0000\u0000\u0000\u0001ဈ\u0000", new Object[]{"zzc", "zzd"});
        }
        if (iK == 3) {
            return new MB();
        }
        if (iK == 4) {
            return new LB(zza);
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
        synchronized (MB.class) {
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
