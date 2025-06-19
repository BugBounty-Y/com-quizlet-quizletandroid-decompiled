package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.t5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2642t5 extends OA {
    private static final C2642t5 zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private C2728v5 zzd;
    private BA zze;
    private BA zzf;

    static {
        C2642t5 c2642t5 = new C2642t5();
        zza = c2642t5;
        OA.k(C2642t5.class, c2642t5);
    }

    public C2642t5() {
        C2905zA c2905zA = BA.b;
        this.zze = c2905zA;
        this.zzf = c2905zA;
    }

    public static C2642t5 w(C2905zA c2905zA, IA ia) {
        return (C2642t5) OA.o(zza, c2905zA, ia);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0004\u0003\u0000\u0001\u0001\u0003\u0003\u0000\u0000\u0000\u0001ဉ\u0000\u0002ည\u0001\u0003ည\u0002", new Object[]{"zzc", "zzd", "zze", "zzf"});
        }
        if (iK == 3) {
            return new C2642t5();
        }
        if (iK == 4) {
            return new W3(zza);
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
        synchronized (C2642t5.class) {
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

    public final C2728v5 x() {
        C2728v5 c2728v5 = this.zzd;
        return c2728v5 == null ? C2728v5.A() : c2728v5;
    }

    public final BA y() {
        return this.zzf;
    }

    public final BA z() {
        return this.zze;
    }
}
