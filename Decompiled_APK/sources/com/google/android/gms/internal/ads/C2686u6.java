package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.u6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2686u6 extends OA {
    public static final int zza = 1;
    public static final int zzb = 2;
    private static final C2686u6 zzc;
    private static volatile InterfaceC2219jB zzd;
    private int zze;
    private int zzf;
    private int zzg;

    static {
        C2686u6 c2686u6 = new C2686u6();
        zzc = c2686u6;
        OA.k(C2686u6.class, c2686u6);
    }

    public static C2643t6 w() {
        return (C2643t6) zzc.g();
    }

    public static void x(C2686u6 c2686u6, int i) {
        c2686u6.getClass();
        int i2 = 1;
        if (i == 1) {
            i2 = 0;
        } else if (i != 2) {
            if (i != 3) {
                i2 = 4;
                if (i != 4) {
                    throw null;
                }
            } else {
                i2 = 2;
            }
        }
        c2686u6.zzg = i2;
        c2686u6.zze |= 2;
    }

    public static void y(C2686u6 c2686u6, int i) {
        c2686u6.getClass();
        c2686u6.zzf = AbstractC0147y.k(i);
        c2686u6.zze |= 1;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zzc, "\u0004\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0000\u0000\u0001᠌\u0000\u0002᠌\u0001", new Object[]{"zze", "zzf", U3.n, "zzg", U3.m});
        }
        if (iK == 3) {
            return new C2686u6();
        }
        if (iK == 4) {
            return new C2643t6(zzc);
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
        synchronized (C2686u6.class) {
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
