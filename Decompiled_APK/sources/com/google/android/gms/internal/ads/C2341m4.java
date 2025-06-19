package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.m4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2341m4 extends OA {
    private static final C2341m4 zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private long zzd = -1;
    private long zze = -1;
    private long zzf = -1;
    private long zzg = -1;
    private long zzh = -1;
    private long zzi = -1;
    private long zzj = -1;
    private long zzk = -1;

    static {
        C2341m4 c2341m4 = new C2341m4();
        zza = c2341m4;
        OA.k(C2341m4.class, c2341m4);
    }

    public static /* synthetic */ void A(C2341m4 c2341m4, long j) {
        c2341m4.zzc |= 8;
        c2341m4.zzg = j;
    }

    public static /* synthetic */ void B(C2341m4 c2341m4, long j) {
        c2341m4.zzc |= 16;
        c2341m4.zzh = j;
    }

    public static C2298l4 w() {
        return (C2298l4) zza.g();
    }

    public static /* synthetic */ void x(C2341m4 c2341m4, long j) {
        c2341m4.zzc |= 32;
        c2341m4.zzi = j;
    }

    public static /* synthetic */ void y(C2341m4 c2341m4, long j) {
        c2341m4.zzc |= 4;
        c2341m4.zzf = j;
    }

    public static /* synthetic */ void z(C2341m4 c2341m4, long j) {
        c2341m4.zzc |= 1;
        c2341m4.zzd = j;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0001\b\u0000\u0001\u0001\b\b\u0000\u0000\u0000\u0001ဂ\u0000\u0002ဂ\u0001\u0003ဂ\u0002\u0004ဂ\u0003\u0005ဂ\u0004\u0006ဂ\u0005\u0007ဂ\u0006\bဂ\u0007", new Object[]{"zzc", "zzd", "zze", "zzf", "zzg", "zzh", "zzi", "zzj", "zzk"});
        }
        if (iK == 3) {
            return new C2341m4();
        }
        if (iK == 4) {
            return new C2298l4(zza);
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
        synchronized (C2341m4.class) {
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
