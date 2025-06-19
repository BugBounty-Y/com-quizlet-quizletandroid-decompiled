package com.google.android.gms.internal.ads;

import android.os.Build;
import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class A6 extends OA {
    public static final int zza = 1;
    public static final int zzb = 2;
    public static final int zzc = 3;
    public static final int zzd = 4;
    public static final int zze = 5;
    public static final int zzf = 6;
    public static final int zzg = 7;
    public static final int zzh = 8;
    private static final A6 zzi;
    private static volatile InterfaceC2219jB zzj;
    private int zzk;
    private int zzm;
    private int zzn;
    private long zzo;
    private long zzv;
    private int zzw;
    private VA zzl = C2348mB.e;
    private String zzp = "";
    private String zzu = "";

    static {
        A6 a6 = new A6();
        zzi = a6;
        OA.k(A6.class, a6);
    }

    public static void A(A6 a6, int i) {
        a6.zzk |= 1;
        a6.zzm = i;
    }

    public static void B(A6 a6, long j) {
        a6.zzk |= 32;
        a6.zzv = j;
    }

    public static void C(A6 a6, int i) {
        a6.zzk |= 2;
        a6.zzn = i;
    }

    public static void D(A6 a6, long j) {
        a6.zzk |= 4;
        a6.zzo = j;
    }

    public static C2858y6 E() {
        return (C2858y6) zzi.g();
    }

    public static void w(A6 a6, ArrayList arrayList) {
        VA va = a6.zzl;
        if (!((AbstractC2690uA) va).a) {
            int size = va.size();
            a6.zzl = va.d(size + size);
        }
        AbstractC2647tA.c(arrayList, a6.zzl);
    }

    public static void x(A6 a6, String str) {
        a6.getClass();
        str.getClass();
        a6.zzk |= 8;
        a6.zzp = str;
    }

    public static void y(A6 a6, int i) {
        a6.zzk |= 64;
        a6.zzw = i;
    }

    public static void z(A6 a6) {
        String str = Build.MODEL;
        a6.getClass();
        str.getClass();
        a6.zzk |= 16;
        a6.zzu = str;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zzi, "\u0004\b\u0000\u0001\u0001\b\b\u0000\u0001\u0000\u0001\u001b\u0002င\u0000\u0003င\u0001\u0004ဂ\u0002\u0005ဈ\u0003\u0006ဈ\u0004\u0007ဂ\u0005\bင\u0006", new Object[]{"zzk", "zzl", C2815x6.class, "zzm", "zzn", "zzo", "zzp", "zzu", "zzv", "zzw"});
        }
        if (iK == 3) {
            return new A6();
        }
        if (iK == 4) {
            return new C2858y6(zzi);
        }
        if (iK == 5) {
            return zzi;
        }
        if (iK != 6) {
            throw null;
        }
        InterfaceC2219jB interfaceC2219jB = zzj;
        if (interfaceC2219jB != null) {
            return interfaceC2219jB;
        }
        synchronized (A6.class) {
            try {
                na = zzj;
                if (na == null) {
                    na = new NA();
                    zzj = na;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return na;
    }
}
