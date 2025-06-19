package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.fz, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2076fz extends OA {
    private static final C2076fz zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private int zzd;
    private C2249jz zze;
    private BA zzf = BA.b;

    static {
        C2076fz c2076fz = new C2076fz();
        zza = c2076fz;
        OA.k(C2076fz.class, c2076fz);
    }

    public static InterfaceC2219jB B() {
        return zza.h();
    }

    public static /* synthetic */ void D(C2076fz c2076fz, C2249jz c2249jz) {
        c2076fz.zze = c2249jz;
        c2076fz.zzc |= 1;
    }

    public static C2032ez x() {
        return (C2032ez) zza.g();
    }

    public static C2076fz y(BA ba, IA ia) {
        return (C2076fz) OA.o(zza, ba, ia);
    }

    public final BA A() {
        return this.zzf;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0003\u0000\u0001\u0001\u0003\u0003\u0000\u0000\u0000\u0001\u000b\u0002ဉ\u0000\u0003\n", new Object[]{"zzc", "zzd", "zze", "zzf"});
        }
        if (iK == 3) {
            return new C2076fz();
        }
        if (iK == 4) {
            return new C2032ez(zza);
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
        synchronized (C2076fz.class) {
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
        return this.zzd;
    }

    public final C2249jz z() {
        C2249jz c2249jz = this.zze;
        return c2249jz == null ? C2249jz.y() : c2249jz;
    }
}
