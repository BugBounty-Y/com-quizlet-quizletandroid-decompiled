package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.ar, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1850ar extends OA {
    private static final C1850ar zza;
    private static volatile InterfaceC2219jB zzb;
    private VA zzc = C2348mB.e;

    static {
        C1850ar c1850ar = new C1850ar();
        zza = c1850ar;
        OA.k(C1850ar.class, c1850ar);
    }

    public static Xq x() {
        return (Xq) zza.g();
    }

    public static void y(C1850ar c1850ar, Zq zq) {
        VA va = c1850ar.zzc;
        if (!((AbstractC2690uA) va).a) {
            int size = va.size();
            c1850ar.zzc = va.d(size + size);
        }
        c1850ar.zzc.add(zq);
    }

    public static void z(C1850ar c1850ar) {
        c1850ar.zzc = C2348mB.e;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0004\u0001\u0000\u0000\u0001\u0001\u0001\u0000\u0001\u0000\u0001\u001b", new Object[]{"zzc", Zq.class});
        }
        if (iK == 3) {
            return new C1850ar();
        }
        if (iK == 4) {
            return new Xq(zza);
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
        synchronized (C1850ar.class) {
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

    public final int w() {
        return this.zzc.size();
    }
}
