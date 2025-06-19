package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import java.util.RandomAccess;

/* renamed from: com.google.android.gms.internal.ads.m7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2344m7 extends OA {
    public static final int zza = 9;
    public static final int zzb = 10;
    public static final int zzc = 11;
    public static final int zzd = 12;
    public static final int zze = 13;
    public static final int zzf = 14;
    public static final int zzg = 15;
    public static final int zzh = 16;
    public static final int zzi = 17;
    public static final int zzj = 18;
    public static final int zzk = 19;
    public static final int zzl = 20;
    public static final int zzm = 21;
    private static final C2344m7 zzn;
    private static volatile InterfaceC2219jB zzo;
    private C2215j7 zzA;
    private C2258k7 zzB;
    private C2686u6 zzC;
    private C2600s6 zzD;
    private A6 zzE;
    private C1823a7 zzF;
    private T6 zzG;
    private int zzp;
    private int zzu;
    private int zzw;
    private H6 zzy;
    private String zzv = "";
    private int zzx = 1000;
    private UA zzz = C1827aB.e;

    static {
        C2344m7 c2344m7 = new C2344m7();
        zzn = c2344m7;
        OA.k(C2344m7.class, c2344m7);
    }

    public static void A(C2344m7 c2344m7, C2215j7 c2215j7) {
        c2344m7.getClass();
        c2344m7.zzA = c2215j7;
        c2344m7.zzp |= 32;
    }

    public static void B(C2344m7 c2344m7, A6 a6) {
        c2344m7.getClass();
        c2344m7.zzE = a6;
        c2344m7.zzp |= com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH;
    }

    public static void C(C2344m7 c2344m7, C1823a7 c1823a7) {
        c2344m7.getClass();
        c2344m7.zzF = c1823a7;
        c2344m7.zzp |= 1024;
    }

    public static void D(C2344m7 c2344m7, String str) {
        c2344m7.getClass();
        str.getClass();
        c2344m7.zzp |= 2;
        c2344m7.zzv = str;
    }

    public static C2301l7 H() {
        return (C2301l7) zzn.g();
    }

    public static void w(C2344m7 c2344m7, ArrayList arrayList) {
        RandomAccess randomAccess = c2344m7.zzz;
        if (!((AbstractC2690uA) randomAccess).a) {
            C1827aB c1827aB = (C1827aB) randomAccess;
            int i = c1827aB.c;
            c2344m7.zzz = c1827aB.d(i + i);
        }
        AbstractC2647tA.c(arrayList, c2344m7.zzz);
    }

    public static void x(C2344m7 c2344m7) {
        c2344m7.getClass();
        c2344m7.zzz = C1827aB.e;
    }

    public static void y(C2344m7 c2344m7, C2600s6 c2600s6) {
        c2344m7.getClass();
        c2344m7.zzD = c2600s6;
        c2344m7.zzp |= 256;
    }

    public static void z(C2344m7 c2344m7, T6 t6) {
        c2344m7.getClass();
        c2344m7.zzG = t6;
        c2344m7.zzp |= 2048;
    }

    public final String E() {
        return this.zzv;
    }

    public final C2600s6 F() {
        C2600s6 c2600s6 = this.zzD;
        return c2600s6 == null ? C2600s6.z() : c2600s6;
    }

    public final C2215j7 G() {
        C2215j7 c2215j7 = this.zzA;
        return c2215j7 == null ? C2215j7.y() : c2215j7;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zzn, "\u0004\r\u0000\u0001\t\u0015\r\u0000\u0001\u0000\tင\u0000\nဈ\u0001\u000bဋ\u0002\f᠌\u0003\rဉ\u0004\u000e\u0015\u000fဉ\u0005\u0010ဉ\u0006\u0011ဉ\u0007\u0012ဉ\b\u0013ဉ\t\u0014ဉ\n\u0015ဉ\u000b", new Object[]{"zzp", "zzu", "zzv", "zzw", "zzx", U3.t, "zzy", "zzz", "zzA", "zzB", "zzC", "zzD", "zzE", "zzF", "zzG"});
        }
        if (iK == 3) {
            return new C2344m7();
        }
        if (iK == 4) {
            return new C2301l7(zzn);
        }
        if (iK == 5) {
            return zzn;
        }
        if (iK != 6) {
            throw null;
        }
        InterfaceC2219jB interfaceC2219jB = zzo;
        if (interfaceC2219jB != null) {
            return interfaceC2219jB;
        }
        synchronized (C2344m7.class) {
            try {
                na = zzo;
                if (na == null) {
                    na = new NA();
                    zzo = na;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return na;
    }
}
