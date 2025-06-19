package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.t4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2641t4 extends OA {
    private static final C2641t4 zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private long zzf;
    private long zzh;
    private long zzi;
    private String zzd = "";
    private String zze = "";
    private String zzg = "D";

    static {
        C2641t4 c2641t4 = new C2641t4();
        zza = c2641t4;
        OA.k(C2641t4.class, c2641t4);
    }

    public static /* synthetic */ void A(C2641t4 c2641t4, long j) {
        c2641t4.zzc |= 4;
        c2641t4.zzf = j;
    }

    public static /* synthetic */ void B(C2641t4 c2641t4, long j) {
        c2641t4.zzc |= 32;
        c2641t4.zzi = j;
    }

    public static /* synthetic */ void C(C2641t4 c2641t4, long j) {
        c2641t4.zzc |= 16;
        c2641t4.zzh = j;
    }

    public static C2598s4 w() {
        return (C2598s4) zza.g();
    }

    public static /* synthetic */ void x(C2641t4 c2641t4) {
        c2641t4.zzc |= 1;
        c2641t4.zzd = "0.460000000";
    }

    public static /* synthetic */ void y(C2641t4 c2641t4, String str) {
        str.getClass();
        c2641t4.zzc |= 2;
        c2641t4.zze = str;
    }

    public static /* synthetic */ void z(C2641t4 c2641t4, String str) {
        str.getClass();
        c2641t4.zzc |= 8;
        c2641t4.zzg = str;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0001\u0006\u0000\u0001\u0001\u0006\u0006\u0000\u0000\u0000\u0001ဈ\u0000\u0002ဈ\u0001\u0003ဂ\u0002\u0004ဈ\u0003\u0005ဂ\u0004\u0006ဂ\u0005", new Object[]{"zzc", "zzd", "zze", "zzf", "zzg", "zzh", "zzi"});
        }
        if (iK == 3) {
            return new C2641t4();
        }
        if (iK == 4) {
            return new C2598s4(zza);
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
        synchronized (C2641t4.class) {
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
