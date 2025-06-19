package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class T6 extends OA {
    public static final int zza = 1;
    private static final T6 zzb;
    private static volatile InterfaceC2219jB zzc;
    private VA zzd = C2348mB.e;

    static {
        T6 t6 = new T6();
        zzb = t6;
        OA.k(T6.class, t6);
    }

    public static O6 w() {
        return (O6) zzb.g();
    }

    public static void x(T6 t6, N6 n6) {
        t6.getClass();
        VA va = t6.zzd;
        if (!((AbstractC2690uA) va).a) {
            int size = va.size();
            t6.zzd = va.d(size + size);
        }
        t6.zzd.add(n6);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zzb, "\u0004\u0001\u0000\u0000\u0001\u0001\u0001\u0000\u0001\u0000\u0001\u001b", new Object[]{"zzd", N6.class});
        }
        if (iK == 3) {
            return new T6();
        }
        if (iK == 4) {
            return new O6(zzb);
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
        synchronized (T6.class) {
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
