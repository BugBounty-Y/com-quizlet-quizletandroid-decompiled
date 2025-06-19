package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.x4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2813x4 extends OA {
    private static final C2813x4 zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private VA zzd = C2348mB.e;
    private BA zze = BA.b;
    private int zzf = 1;
    private int zzg = 1;

    static {
        C2813x4 c2813x4 = new C2813x4();
        zza = c2813x4;
        OA.k(C2813x4.class, c2813x4);
    }

    public static /* synthetic */ void A(C2813x4 c2813x4) {
        c2813x4.zzf = 4;
        c2813x4.zzc |= 2;
    }

    public static C2770w4 w() {
        return (C2770w4) zza.g();
    }

    public static void x(C2813x4 c2813x4, C2905zA c2905zA) {
        VA va = c2813x4.zzd;
        if (!((AbstractC2690uA) va).a) {
            int size = va.size();
            c2813x4.zzd = va.d(size + size);
        }
        c2813x4.zzd.add(c2905zA);
    }

    public static /* synthetic */ void y(C2813x4 c2813x4, C2905zA c2905zA) {
        c2813x4.zzc |= 1;
        c2813x4.zze = c2905zA;
    }

    public static /* synthetic */ void z(C2813x4 c2813x4, int i) {
        c2813x4.zzg = i - 1;
        c2813x4.zzc |= 4;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0001\u0004\u0000\u0001\u0001\u0004\u0004\u0000\u0001\u0000\u0001\u001c\u0002ည\u0000\u0003᠌\u0001\u0004᠌\u0002", new Object[]{"zzc", "zzd", "zze", "zzf", U3.k, "zzg", U3.i});
        }
        if (iK == 3) {
            return new C2813x4();
        }
        if (iK == 4) {
            return new C2770w4(zza);
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
        synchronized (C2813x4.class) {
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
