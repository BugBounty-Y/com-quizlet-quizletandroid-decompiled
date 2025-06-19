package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class Tz extends OA {
    private static final Tz zza;
    private static volatile InterfaceC2219jB zzb;
    private String zzc = "";

    static {
        Tz tz = new Tz();
        zza = tz;
        OA.k(Tz.class, tz);
    }

    public static /* synthetic */ void A(Tz tz, String str) {
        str.getClass();
        tz.zzc = str;
    }

    public static Sz w() {
        return (Sz) zza.g();
    }

    public static Tz x() {
        return zza;
    }

    public static Tz y(BA ba, IA ia) {
        return (Tz) OA.o(zza, ba, ia);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0001\u0000\u0000\u0001\u0001\u0001\u0000\u0000\u0000\u0001Ȉ", new Object[]{"zzc"});
        }
        if (iK == 3) {
            return new Tz();
        }
        if (iK == 4) {
            return new Sz(zza);
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
        synchronized (Tz.class) {
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

    public final String z() {
        return this.zzc;
    }
}
