package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class Y3 extends OA {
    private static final Y3 zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private long zze;
    private long zzi;
    private long zzj;
    private long zzl;
    private int zzp;
    private String zzd = "";
    private String zzf = "";
    private String zzg = "";
    private String zzh = "";
    private String zzk = "";
    private String zzm = "";
    private String zzn = "";
    private VA zzo = C2348mB.e;

    static {
        Y3 y3 = new Y3();
        zza = y3;
        OA.k(Y3.class, y3);
    }

    public static /* synthetic */ void A(Y3 y3, String str) {
        y3.zzc |= 8;
        y3.zzg = str;
    }

    public static /* synthetic */ void B(Y3 y3, long j) {
        y3.zzc |= 2;
        y3.zze = j;
    }

    public static /* synthetic */ void C(Y3 y3, String str) {
        str.getClass();
        y3.zzc |= 4;
        y3.zzf = str;
    }

    public static /* synthetic */ void D(Y3 y3, int i) {
        y3.zzp = i - 1;
        y3.zzc |= 2048;
    }

    public static V3 w() {
        return (V3) zza.g();
    }

    public static /* synthetic */ void x(Y3 y3, String str) {
        str.getClass();
        y3.zzc |= 1;
        y3.zzd = str;
    }

    public static /* synthetic */ void y(Y3 y3, String str) {
        y3.zzc |= 16;
        y3.zzh = str;
    }

    public static /* synthetic */ void z(Y3 y3, String str) {
        y3.zzc |= 1024;
        y3.zzn = str;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0004\r\u0000\u0001\u0001\r\r\u0000\u0001\u0000\u0001ဈ\u0000\u0002ဂ\u0001\u0003ဈ\u0002\u0004ဈ\u0003\u0005ဈ\u0004\u0006ဂ\u0005\u0007ဂ\u0006\bဈ\u0007\tဂ\b\nဈ\t\u000bဈ\n\f\u001b\r᠌\u000b", new Object[]{"zzc", "zzd", "zze", "zzf", "zzg", "zzh", "zzi", "zzj", "zzk", "zzl", "zzm", "zzn", "zzo", X3.class, "zzp", U3.c});
        }
        if (iK == 3) {
            return new Y3();
        }
        if (iK == 4) {
            return new V3(zza);
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
        synchronized (Y3.class) {
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
