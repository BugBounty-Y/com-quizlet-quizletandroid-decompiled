package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.a7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1823a7 extends OA {
    public static final int zza = 1;
    public static final int zzb = 2;
    private static final C1823a7 zzc;
    private static volatile InterfaceC2219jB zzd;
    private int zze;
    private boolean zzf;
    private int zzg;

    static {
        C1823a7 c1823a7 = new C1823a7();
        zzc = c1823a7;
        OA.k(C1823a7.class, c1823a7);
    }

    public static Z6 w() {
        return (Z6) zzc.g();
    }

    public static void y(C1823a7 c1823a7, boolean z) {
        c1823a7.zze |= 1;
        c1823a7.zzf = z;
    }

    public static void z(C1823a7 c1823a7, int i) {
        c1823a7.zze |= 2;
        c1823a7.zzg = i;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zzc, "\u0004\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0000\u0000\u0001ဇ\u0000\u0002င\u0001", new Object[]{"zze", "zzf", "zzg"});
        }
        if (iK == 3) {
            return new C1823a7();
        }
        if (iK == 4) {
            return new Z6(zzc);
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
        synchronized (C1823a7.class) {
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

    public final boolean x() {
        return this.zzf;
    }
}
