package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.k4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2255k4 extends OA {
    private static final C2255k4 zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private long zzw;
    private long zzx;
    private long zzd = -1;
    private long zze = -1;
    private long zzf = -1;
    private long zzg = -1;
    private long zzh = -1;
    private long zzi = -1;
    private int zzj = 1000;
    private long zzk = -1;
    private long zzl = -1;
    private long zzm = -1;
    private int zzn = 1000;
    private long zzo = -1;
    private long zzp = -1;
    private long zzu = -1;
    private long zzv = -1;
    private long zzy = -1;
    private long zzz = -1;
    private long zzA = -1;
    private long zzB = -1;

    static {
        C2255k4 c2255k4 = new C2255k4();
        zza = c2255k4;
        OA.k(C2255k4.class, c2255k4);
    }

    public static /* synthetic */ void A(C2255k4 c2255k4, long j) {
        c2255k4.zzc |= 4096;
        c2255k4.zzp = j;
    }

    public static /* synthetic */ void B(C2255k4 c2255k4, long j) {
        c2255k4.zzc |= com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH;
        c2255k4.zzm = j;
    }

    public static /* synthetic */ void C(C2255k4 c2255k4, long j) {
        c2255k4.zzc |= 2048;
        c2255k4.zzo = j;
    }

    public static /* synthetic */ void D(C2255k4 c2255k4, long j) {
        c2255k4.zzc |= 4;
        c2255k4.zzf = j;
    }

    public static /* synthetic */ void E(C2255k4 c2255k4, long j) {
        c2255k4.zzc |= 16;
        c2255k4.zzh = j;
    }

    public static /* synthetic */ void F(C2255k4 c2255k4, long j) {
        c2255k4.zzc |= 128;
        c2255k4.zzk = j;
    }

    public static /* synthetic */ void G(C2255k4 c2255k4, long j) {
        c2255k4.zzc |= 131072;
        c2255k4.zzy = j;
    }

    public static /* synthetic */ void H(C2255k4 c2255k4, long j) {
        c2255k4.zzc |= 1;
        c2255k4.zzd = j;
    }

    public static /* synthetic */ void I(C2255k4 c2255k4, long j) {
        c2255k4.zzc |= 262144;
        c2255k4.zzz = j;
    }

    public static /* synthetic */ void J(C2255k4 c2255k4, long j) {
        c2255k4.zzc |= 2;
        c2255k4.zze = j;
    }

    public static /* synthetic */ void K(C2255k4 c2255k4, long j) {
        c2255k4.zzc |= 256;
        c2255k4.zzl = j;
    }

    public static /* synthetic */ void L(C2255k4 c2255k4, long j) {
        c2255k4.zzc |= 32768;
        c2255k4.zzw = j;
    }

    public static /* synthetic */ void M(C2255k4 c2255k4, long j) {
        c2255k4.zzc |= 65536;
        c2255k4.zzx = j;
    }

    public static /* synthetic */ void N(C2255k4 c2255k4, long j) {
        c2255k4.zzc |= 8192;
        c2255k4.zzu = j;
    }

    public static /* synthetic */ void O(C2255k4 c2255k4, long j) {
        c2255k4.zzc |= 16384;
        c2255k4.zzv = j;
    }

    public static /* synthetic */ void P(C2255k4 c2255k4, int i) {
        c2255k4.zzn = i - 1;
        c2255k4.zzc |= 1024;
    }

    public static /* synthetic */ void Q(C2255k4 c2255k4, int i) {
        c2255k4.zzj = i - 1;
        c2255k4.zzc |= 64;
    }

    public static C2212j4 w() {
        return (C2212j4) zza.g();
    }

    public static /* synthetic */ void x(C2255k4 c2255k4) {
        c2255k4.zzc &= -9;
        c2255k4.zzg = -1L;
    }

    public static /* synthetic */ void y(C2255k4 c2255k4, long j) {
        c2255k4.zzc |= 8;
        c2255k4.zzg = j;
    }

    public static /* synthetic */ void z(C2255k4 c2255k4, long j) {
        c2255k4.zzc |= 32;
        c2255k4.zzi = j;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            U3 u3 = U3.j;
            return new C2391nB(zza, "\u0001\u0015\u0000\u0001\u0001\u0015\u0015\u0000\u0000\u0000\u0001ဂ\u0000\u0002ဂ\u0001\u0003ဂ\u0002\u0004ဂ\u0003\u0005ဂ\u0004\u0006ဂ\u0005\u0007᠌\u0006\bဂ\u0007\tဂ\b\nဂ\t\u000b᠌\n\fဂ\u000b\rဂ\f\u000eဂ\r\u000fဂ\u000e\u0010ဂ\u000f\u0011ဂ\u0010\u0012ဂ\u0011\u0013ဂ\u0012\u0014ဂ\u0013\u0015ဂ\u0014", new Object[]{"zzc", "zzd", "zze", "zzf", "zzg", "zzh", "zzi", "zzj", u3, "zzk", "zzl", "zzm", "zzn", u3, "zzo", "zzp", "zzu", "zzv", "zzw", "zzx", "zzy", "zzz", "zzA", "zzB"});
        }
        if (iK == 3) {
            return new C2255k4();
        }
        if (iK == 4) {
            return new C2212j4(zza);
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
        synchronized (C2255k4.class) {
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
