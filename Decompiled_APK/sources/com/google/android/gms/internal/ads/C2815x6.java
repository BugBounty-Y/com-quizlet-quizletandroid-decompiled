package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.RandomAccess;

/* renamed from: com.google.android.gms.internal.ads.x6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2815x6 extends OA {
    public static final int zza = 1;
    public static final int zzb = 2;
    public static final int zzc = 3;
    public static final int zzd = 4;
    public static final int zze = 5;
    public static final int zzf = 6;
    public static final int zzg = 7;
    public static final int zzh = 8;
    public static final int zzi = 9;
    public static final int zzj = 10;
    public static final int zzk = 11;
    public static final int zzl = 12;
    public static final int zzm = 13;
    private static final TA zzn = new C1(26);
    private static final C2815x6 zzo;
    private static volatile InterfaceC2219jB zzp;
    private C2686u6 zzA;
    private int zzB;
    private int zzC;
    private int zzD;
    private int zzE;
    private int zzF;
    private int zzG;
    private long zzH;
    private int zzu;
    private long zzv;
    private int zzw;
    private long zzx;
    private long zzy;
    private SA zzz = PA.e;

    static {
        C2815x6 c2815x6 = new C2815x6();
        zzo = c2815x6;
        OA.k(C2815x6.class, c2815x6);
    }

    public static void A(C2815x6 c2815x6, EnumC2901z6 enumC2901z6) {
        c2815x6.getClass();
        c2815x6.zzG = enumC2901z6.a;
        c2815x6.zzu |= 1024;
    }

    public static void B(C2815x6 c2815x6, C2686u6 c2686u6) {
        c2815x6.getClass();
        c2815x6.zzA = c2686u6;
        c2815x6.zzu |= 16;
    }

    public static void C(C2815x6 c2815x6, int i) {
        c2815x6.getClass();
        c2815x6.zzF = AbstractC1642h.e(i);
        c2815x6.zzu |= com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH;
    }

    public static void D(C2815x6 c2815x6, long j) {
        c2815x6.zzu |= 8;
        c2815x6.zzy = j;
    }

    public static void E(C2815x6 c2815x6, long j) {
        c2815x6.zzu |= 4;
        c2815x6.zzx = j;
    }

    public static void F(C2815x6 c2815x6, int i) {
        c2815x6.getClass();
        c2815x6.zzw = AbstractC1642h.e(i);
        c2815x6.zzu |= 2;
    }

    public static void G(C2815x6 c2815x6, long j) {
        c2815x6.zzu |= 1;
        c2815x6.zzv = j;
    }

    public static void H(C2815x6 c2815x6, long j) {
        c2815x6.zzu |= 2048;
        c2815x6.zzH = j;
    }

    public static void I(C2815x6 c2815x6, int i) {
        c2815x6.getClass();
        c2815x6.zzB = AbstractC1642h.e(i);
        c2815x6.zzu |= 32;
    }

    public static C2772w6 L() {
        return (C2772w6) zzo.g();
    }

    public static C2815x6 M(byte[] bArr) throws zzgzh {
        C2815x6 c2815x6 = zzo;
        int length = bArr.length;
        IA ia = IA.a;
        C2305lB c2305lB = C2305lB.c;
        OA oaU = OA.u(c2815x6, bArr, length, IA.b);
        OA.t(oaU);
        return (C2815x6) oaU;
    }

    public static void w(C2815x6 c2815x6, ArrayList arrayList) {
        RandomAccess randomAccess = c2815x6.zzz;
        if (!((AbstractC2690uA) randomAccess).a) {
            PA pa = (PA) randomAccess;
            int i = pa.c;
            c2815x6.zzz = pa.d(i + i);
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            EnumC1867b7 enumC1867b7 = (EnumC1867b7) it2.next();
            ((PA) c2815x6.zzz).e(enumC1867b7.a);
        }
    }

    public static void x(C2815x6 c2815x6, int i) {
        c2815x6.getClass();
        c2815x6.zzC = AbstractC1642h.e(i);
        c2815x6.zzu |= 64;
    }

    public static void y(C2815x6 c2815x6, int i) {
        c2815x6.getClass();
        c2815x6.zzD = AbstractC1642h.e(i);
        c2815x6.zzu |= 128;
    }

    public static void z(C2815x6 c2815x6, int i) {
        c2815x6.zzu |= 256;
        c2815x6.zzE = i;
    }

    public final long J() {
        return this.zzv;
    }

    public final int K() {
        int i = this.zzw;
        int i2 = i != 0 ? i != 1 ? i != 1000 ? 0 : 3 : 2 : 1;
        if (i2 == 0) {
            return 1;
        }
        return i2;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            U3 u3 = U3.t;
            return new C2391nB(zzo, "\u0004\r\u0000\u0001\u0001\r\r\u0000\u0001\u0000\u0001ဂ\u0000\u0002᠌\u0001\u0003ဂ\u0002\u0004ဂ\u0003\u0005ࠞ\u0006ဉ\u0004\u0007᠌\u0005\b᠌\u0006\t᠌\u0007\nင\b\u000b᠌\t\f᠌\n\rဂ\u000b", new Object[]{"zzu", "zzv", "zzw", u3, "zzx", "zzy", "zzz", U3.r, "zzA", "zzB", u3, "zzC", u3, "zzD", u3, "zzE", "zzF", u3, "zzG", U3.o, "zzH"});
        }
        if (iK == 3) {
            return new C2815x6();
        }
        if (iK == 4) {
            return new C2772w6(zzo);
        }
        if (iK == 5) {
            return zzo;
        }
        if (iK != 6) {
            throw null;
        }
        InterfaceC2219jB interfaceC2219jB = zzp;
        if (interfaceC2219jB != null) {
            return interfaceC2219jB;
        }
        synchronized (C2815x6.class) {
            try {
                na = zzp;
                if (na == null) {
                    na = new NA();
                    zzp = na;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return na;
    }
}
