package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class Q6 extends OA {
    public static final int zza = 1;
    public static final int zzb = 2;
    private static final Q6 zzc;
    private static volatile InterfaceC2219jB zzd;
    private int zze;
    private boolean zzf;
    private int zzg;

    static {
        Q6 q6 = new Q6();
        zzc = q6;
        OA.k(Q6.class, q6);
    }

    public static P6 w() {
        return (P6) zzc.g();
    }

    public static Q6 x() {
        return zzc;
    }

    public static void y(Q6 q6, boolean z) {
        q6.zze |= 1;
        q6.zzf = z;
    }

    public static void z(Q6 q6, int i) {
        q6.zze |= 2;
        q6.zzg = i;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zzc, "\u0004\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0000\u0000\u0001ဇ\u0000\u0002ဋ\u0001", new Object[]{"zze", "zzf", "zzg"});
        }
        if (iK == 3) {
            return new Q6();
        }
        if (iK == 4) {
            return new P6(zzc);
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
        synchronized (Q6.class) {
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
