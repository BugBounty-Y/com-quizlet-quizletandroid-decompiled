package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.uz, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2721uz extends OA {
    private static final C2721uz zza;
    private static volatile InterfaceC2219jB zzb;

    static {
        C2721uz c2721uz = new C2721uz();
        zza = c2721uz;
        OA.k(C2721uz.class, c2721uz);
    }

    public static C2721uz w() {
        return zza;
    }

    public static void x(BA ba, IA ia) {
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0000", null);
        }
        if (iK == 3) {
            return new C2721uz();
        }
        if (iK == 4) {
            return new C1954d7(zza);
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
        synchronized (C2721uz.class) {
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
