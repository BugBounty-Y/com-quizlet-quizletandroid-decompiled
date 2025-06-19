package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.u4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2684u4 extends OA {
    private static final C2684u4 zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private long zzd;
    private String zze = "";
    private BA zzf = BA.b;

    static {
        C2684u4 c2684u4 = new C2684u4();
        zza = c2684u4;
        OA.k(C2684u4.class, c2684u4);
    }

    public static C2684u4 x() {
        return zza;
    }

    public final boolean A() {
        return (this.zzc & 1) != 0;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0001\u0003\u0000\u0001\u0001\u0004\u0003\u0000\u0000\u0000\u0001ဂ\u0000\u0003ဈ\u0001\u0004ည\u0002", new Object[]{"zzc", "zzd", "zze", "zzf"});
        }
        if (iK == 3) {
            return new C2684u4();
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
        synchronized (C2684u4.class) {
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

    public final long w() {
        return this.zzd;
    }

    public final BA y() {
        return this.zzf;
    }

    public final String z() {
        return this.zze;
    }
}
