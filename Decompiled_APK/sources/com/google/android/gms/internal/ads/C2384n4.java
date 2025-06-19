package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.n4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2384n4 extends OA {
    private static final C2384n4 zza;
    private static volatile InterfaceC2219jB zzb;
    private long zzA;
    private long zzB;
    private long zzC;
    private long zzD;
    private long zzE;
    private long zzF;
    private long zzJ;
    private long zzK;
    private long zzL;
    private long zzN;
    private C2427o4 zzQ;
    private long zzaA;
    private int zzaB;
    private int zzaC;
    private String zzaD;
    private VA zzaE;
    private int zzaF;
    private VA zzaG;
    private C2170i4 zzaH;
    private C2126h4 zzaI;
    private String zzaJ;
    private long zzaK;
    private long zzaL;
    private long zzaM;
    private long zzaN;
    private long zzaO;
    private long zzaP;
    private long zzaQ;
    private String zzaR;
    private C1951d4 zzaS;
    private C1994e4 zzaT;
    private long zzaU;
    private long zzaV;
    private int zzaW;
    private long zzaX;
    private String zzaY;
    private int zzaZ;
    private C2255k4 zzai;
    private VA zzaj;
    private C2341m4 zzak;
    private long zzal;
    private long zzam;
    private long zzan;
    private long zzao;
    private long zzap;
    private long zzaq;
    private long zzar;
    private long zzas;
    private String zzat;
    private long zzau;
    private int zzav;
    private int zzaw;
    private int zzax;
    private int zzay;
    private C2727v4 zzaz;
    private boolean zzba;
    private String zzbb;
    private long zzbc;
    private C2684u4 zzbd;
    private long zzbe;
    private String zzbf;
    private int zzc;
    private int zzd;
    private int zze;
    private int zzf;
    private long zzi;
    private long zzj;
    private long zzk;
    private long zzl;
    private long zzm;
    private long zzn;
    private long zzo;
    private long zzp;
    private long zzu;
    private long zzv;
    private long zzx;
    private long zzy;
    private long zzz;
    private String zzg = "";
    private String zzh = "";
    private String zzw = "";
    private String zzG = "";
    private String zzH = "D";
    private String zzI = "";
    private String zzM = "";
    private long zzO = -1;
    private long zzP = -1;
    private long zzR = -1;
    private long zzS = -1;
    private long zzT = -1;
    private long zzU = -1;
    private long zzV = -1;
    private long zzW = -1;
    private String zzX = "D";
    private String zzY = "D";
    private long zzZ = -1;
    private int zzaa = 1000;
    private int zzab = 1000;
    private long zzac = -1;
    private long zzad = -1;
    private long zzae = -1;
    private long zzaf = -1;
    private long zzag = -1;
    private int zzah = 1000;

    static {
        C2384n4 c2384n4 = new C2384n4();
        zza = c2384n4;
        OA.k(C2384n4.class, c2384n4);
    }

    public C2384n4() {
        C2348mB c2348mB = C2348mB.e;
        this.zzaj = c2348mB;
        this.zzal = -1L;
        this.zzam = -1L;
        this.zzan = -1L;
        this.zzao = -1L;
        this.zzap = -1L;
        this.zzaq = -1L;
        this.zzar = -1L;
        this.zzas = -1L;
        this.zzat = "D";
        this.zzau = -1L;
        this.zzaA = -1L;
        this.zzaB = 1000;
        this.zzaC = 1000;
        this.zzaD = "D";
        this.zzaE = c2348mB;
        this.zzaF = 1000;
        this.zzaG = c2348mB;
        this.zzaJ = "";
        this.zzaK = -1L;
        this.zzaL = -1L;
        this.zzaM = -1L;
        this.zzaN = -1L;
        this.zzaQ = -1L;
        this.zzaR = "";
        this.zzaU = -1L;
        this.zzaV = -1L;
        this.zzaY = "";
        this.zzaZ = 2;
        this.zzbb = "";
        this.zzbe = -1L;
        this.zzbf = "";
    }

    public static /* synthetic */ void A(C2384n4 c2384n4, long j) {
        c2384n4.zzc |= 1024;
        c2384n4.zzu = j;
    }

    public static /* synthetic */ void A0(C2384n4 c2384n4, long j) {
        c2384n4.zzc |= 16;
        c2384n4.zzk = j;
    }

    public static /* synthetic */ void B(C2384n4 c2384n4, long j) {
        c2384n4.zzc |= 2048;
        c2384n4.zzv = j;
    }

    public static /* synthetic */ void B0(C2384n4 c2384n4, String str) {
        str.getClass();
        c2384n4.zzc |= 16777216;
        c2384n4.zzI = str;
    }

    public static /* synthetic */ void C(C2384n4 c2384n4, String str) {
        str.getClass();
        c2384n4.zzc |= 1;
        c2384n4.zzg = str;
    }

    public static /* synthetic */ void C0(C2384n4 c2384n4, long j) {
        c2384n4.zzd |= 32;
        c2384n4.zzV = j;
    }

    public static /* synthetic */ void D(C2384n4 c2384n4, long j) {
        c2384n4.zzd |= 4194304;
        c2384n4.zzan = j;
    }

    public static /* synthetic */ void D0(C2384n4 c2384n4, long j) {
        c2384n4.zzd |= 4096;
        c2384n4.zzac = j;
    }

    public static /* synthetic */ void E(C2384n4 c2384n4, long j) {
        c2384n4.zzc |= 524288;
        c2384n4.zzD = j;
    }

    public static /* synthetic */ void E0(C2384n4 c2384n4, long j) {
        c2384n4.zzd |= 8192;
        c2384n4.zzad = j;
    }

    public static /* synthetic */ void F(C2384n4 c2384n4, long j) {
        c2384n4.zzd |= 8388608;
        c2384n4.zzao = j;
    }

    public static /* synthetic */ void F0(C2384n4 c2384n4, long j) {
        c2384n4.zze |= 536870912;
        c2384n4.zzbc = j;
    }

    public static /* synthetic */ void G(C2384n4 c2384n4, long j) {
        c2384n4.zzd |= 64;
        c2384n4.zzW = j;
    }

    public static /* synthetic */ void G0(C2384n4 c2384n4, long j) {
        c2384n4.zze |= 16384;
        c2384n4.zzaN = j;
    }

    public static /* synthetic */ void H(C2384n4 c2384n4, long j) {
        c2384n4.zzd |= 16;
        c2384n4.zzU = j;
    }

    public static /* synthetic */ void I(C2384n4 c2384n4, long j) {
        c2384n4.zzc |= Integer.MIN_VALUE;
        c2384n4.zzP = j;
    }

    public static /* synthetic */ void J(C2384n4 c2384n4, long j) {
        c2384n4.zzd |= 8;
        c2384n4.zzT = j;
    }

    public static /* synthetic */ void K(C2384n4 c2384n4, long j) {
        c2384n4.zzd |= 4;
        c2384n4.zzS = j;
    }

    public static /* synthetic */ void L(C2384n4 c2384n4, long j) {
        c2384n4.zzc |= 1073741824;
        c2384n4.zzO = j;
    }

    public static /* synthetic */ void M(C2384n4 c2384n4, long j) {
        c2384n4.zzc |= 32768;
        c2384n4.zzz = j;
    }

    public static /* synthetic */ void N(C2384n4 c2384n4, long j) {
        c2384n4.zzd |= 2;
        c2384n4.zzR = j;
    }

    public static /* synthetic */ void O(C2384n4 c2384n4, long j) {
        c2384n4.zzc |= 8192;
        c2384n4.zzx = j;
    }

    public static /* synthetic */ void P(C2384n4 c2384n4, long j) {
        c2384n4.zzc |= 16384;
        c2384n4.zzy = j;
    }

    public static /* synthetic */ void Q(C2384n4 c2384n4, long j) {
        c2384n4.zzd |= 16384;
        c2384n4.zzae = j;
    }

    public static /* synthetic */ void R(C2384n4 c2384n4, long j) {
        c2384n4.zze |= 2048;
        c2384n4.zzaK = j;
    }

    public static /* synthetic */ void S(C2384n4 c2384n4, C2255k4 c2255k4) {
        c2384n4.zzai = c2255k4;
        c2384n4.zzd |= 262144;
    }

    public static /* synthetic */ void T(C2384n4 c2384n4, long j) {
        c2384n4.zzc |= 67108864;
        c2384n4.zzK = j;
    }

    public static /* synthetic */ void U(C2384n4 c2384n4, long j) {
        c2384n4.zzc |= 65536;
        c2384n4.zzA = j;
    }

    public static /* synthetic */ void V(C2384n4 c2384n4, long j) {
        c2384n4.zzc |= 2097152;
        c2384n4.zzF = j;
    }

    public static C1864b4 W() {
        return (C1864b4) zza.g();
    }

    public static /* synthetic */ void X(C2384n4 c2384n4, long j) {
        c2384n4.zzc |= 134217728;
        c2384n4.zzL = j;
    }

    public static /* synthetic */ void Y(C2384n4 c2384n4, long j) {
        c2384n4.zzc |= 33554432;
        c2384n4.zzJ = j;
    }

    public static /* synthetic */ void Z(C2384n4 c2384n4, long j) {
        c2384n4.zzc |= 536870912;
        c2384n4.zzN = j;
    }

    public static /* synthetic */ void a0(C2384n4 c2384n4, C2341m4 c2341m4) {
        c2384n4.zzak = c2341m4;
        c2384n4.zzd |= 524288;
    }

    public static /* synthetic */ void b0(C2384n4 c2384n4, String str) {
        str.getClass();
        c2384n4.zzc |= 268435456;
        c2384n4.zzM = str;
    }

    public static /* synthetic */ void e0(C2384n4 c2384n4, int i) {
        c2384n4.zzab = i - 1;
        c2384n4.zzd |= 2048;
    }

    public static /* synthetic */ void f0(C2384n4 c2384n4, int i) {
        c2384n4.zzah = i - 1;
        c2384n4.zzd |= 131072;
    }

    public static /* synthetic */ void g0(C2384n4 c2384n4, int i) {
        c2384n4.zzaC = i - 1;
        c2384n4.zze |= 32;
    }

    public static /* synthetic */ void h0(C2384n4 c2384n4, int i) {
        c2384n4.zzaW = i - 1;
        c2384n4.zze |= 8388608;
    }

    public static /* synthetic */ void i0(C2384n4 c2384n4, int i) {
        c2384n4.zzaB = i - 1;
        c2384n4.zze |= 16;
    }

    public static /* synthetic */ void j0(C2384n4 c2384n4, int i) {
        c2384n4.zzaa = i - 1;
        c2384n4.zzd |= 1024;
    }

    public static C2384n4 k0() {
        return zza;
    }

    public static C2384n4 l0(byte[] bArr, IA ia) throws zzgzh {
        OA oaU = OA.u(zza, bArr, bArr.length, ia);
        OA.t(oaU);
        return (C2384n4) oaU;
    }

    public static void o0(C2384n4 c2384n4, C2255k4 c2255k4) {
        VA va = c2384n4.zzaj;
        if (!((AbstractC2690uA) va).a) {
            int size = va.size();
            c2384n4.zzaj = va.d(size + size);
        }
        c2384n4.zzaj.add(c2255k4);
    }

    public static void p0(C2384n4 c2384n4) {
        c2384n4.zzaj = C2348mB.e;
    }

    public static /* synthetic */ void q0(C2384n4 c2384n4, long j) {
        c2384n4.zzd |= 67108864;
        c2384n4.zzar = j;
    }

    public static /* synthetic */ void r0(C2384n4 c2384n4, String str) {
        str.getClass();
        c2384n4.zzd |= 268435456;
        c2384n4.zzat = str;
    }

    public static /* synthetic */ void s0(C2384n4 c2384n4, long j) {
        c2384n4.zzd |= 134217728;
        c2384n4.zzas = j;
    }

    public static /* synthetic */ void t0(C2384n4 c2384n4, long j) {
        c2384n4.zze |= 4096;
        c2384n4.zzaL = j;
    }

    public static /* synthetic */ void u0(C2384n4 c2384n4, String str) {
        str.getClass();
        c2384n4.zze |= 262144;
        c2384n4.zzaR = str;
    }

    public static /* synthetic */ void v0(C2384n4 c2384n4, String str) {
        str.getClass();
        c2384n4.zzc |= 2;
        c2384n4.zzh = str;
    }

    public static /* synthetic */ void w(C2384n4 c2384n4, long j) {
        c2384n4.zze |= 8192;
        c2384n4.zzaM = j;
    }

    public static /* synthetic */ void w0(C2384n4 c2384n4, String str) {
        str.getClass();
        c2384n4.zzd |= 128;
        c2384n4.zzX = str;
    }

    public static /* synthetic */ void x(C2384n4 c2384n4, String str) {
        str.getClass();
        c2384n4.zzd |= 256;
        c2384n4.zzY = str;
    }

    public static /* synthetic */ void x0(C2384n4 c2384n4, long j) {
        c2384n4.zzc |= 4;
        c2384n4.zzi = j;
    }

    public static /* synthetic */ void y(C2384n4 c2384n4, String str) {
        str.getClass();
        c2384n4.zzc |= 4194304;
        c2384n4.zzG = str;
    }

    public static /* synthetic */ void y0(C2384n4 c2384n4, long j) {
        c2384n4.zzd |= 2097152;
        c2384n4.zzam = j;
    }

    public static /* synthetic */ void z(C2384n4 c2384n4, long j) {
        c2384n4.zzc |= 1048576;
        c2384n4.zzE = j;
    }

    public static /* synthetic */ void z0(C2384n4 c2384n4, long j) {
        c2384n4.zzc |= 32;
        c2384n4.zzl = j;
    }

    public final boolean c0() {
        return (this.zzc & 4194304) != 0;
    }

    public final boolean d0() {
        return (this.zze & 1073741824) != 0;
    }

    public final C2684u4 m0() {
        C2684u4 c2684u4 = this.zzbd;
        return c2684u4 == null ? C2684u4.x() : c2684u4;
    }

    public final String n0() {
        return this.zzG;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            U3 u3 = U3.e;
            U3 u32 = U3.j;
            return new C2391nB(zza, "\u0001d\u0000\u0004\u0001Įd\u0000\u0003\u0000\u0001ဈ\u0000\u0002ဈ\u0001\u0003ဂ\u0002\u0004ဂ\u0003\u0005ဂ\u0004\u0006ဂ\u0005\u0007ဂ\u0006\bဂ\u0007\tဂ\b\nဂ\t\u000bဂ\n\fဂ\u000b\rဈ\f\u000eဂ\r\u000fဂ\u000e\u0010ဂ\u000f\u0011ဂ\u0010\u0012ဂ\u0011\u0013ဂ\u0012\u0014ဂ\u0013\u0015ဂX\u0016ဂ\u0014\u0017ဂ\u0015\u0018ဈY\u0019ဂ]\u001a᠌Z\u001bဈ\u0016\u001cဇ[\u001dဈ\u0018\u001eဈ\\\u001fဂ\u0019 ဂ\u001a!ဂ\u001b\"ဈ\u001c#ဂ\u001d$ဂ\u001e%ဂ\u001f&ဉ 'ဂ!(ဂ\")ဂ#*ဂ$+\u001b,ဂ%-ဂ&.ဈ'/ဈ(0᠌*1᠌+2ဉ23ဂ,4ဂ-5ဂ.6ဂ/7ဂ08᠌19ဉ3:ဂ4;ဂ5<ဂ6=ဂ7>ဂ:?ဂ;@ဂ=A᠌>B᠌?Cဈ<D᠌AEဉBFဂCGဂ8Hဂ9I᠌DJဂ)Kဈ\u0017L᠌EMဈFN\u001bO᠌GP\u001bQဉHRဈJSဂKTဂLUဂMVဂNWဂOXဂQYဈRZဉS[ဉT\\ဂU]ဂV^᠌W_᠌@`ဉIaဂPÉဉ^ĭဂ_Įဈ`", new Object[]{"zzc", "zzd", "zze", "zzf", "zzg", "zzh", "zzi", "zzj", "zzk", "zzl", "zzm", "zzn", "zzo", "zzp", "zzu", "zzv", "zzw", "zzx", "zzy", "zzz", "zzA", "zzB", "zzC", "zzD", "zzaX", "zzE", "zzF", "zzaY", "zzbc", "zzaZ", u3, "zzG", "zzba", "zzI", "zzbb", "zzJ", "zzK", "zzL", "zzM", "zzN", "zzO", "zzP", "zzQ", "zzR", "zzS", "zzT", "zzU", "zzaj", C2255k4.class, "zzV", "zzW", "zzX", "zzY", "zzaa", u32, "zzab", u32, "zzai", "zzac", "zzad", "zzae", "zzaf", "zzag", "zzah", u32, "zzak", "zzal", "zzam", "zzan", "zzao", "zzar", "zzas", "zzau", "zzav", U3.i, "zzaw", U3.k, "zzat", "zzay", U3.d, "zzaz", "zzaA", "zzap", "zzaq", "zzaB", u32, "zzZ", "zzH", "zzaC", u32, "zzaD", "zzaE", C2038f4.class, "zzaF", u32, "zzaG", C1907c4.class, "zzaH", "zzaJ", "zzaK", "zzaL", "zzaM", "zzaN", "zzaO", "zzaQ", "zzaR", "zzaS", "zzaT", "zzaU", "zzaV", "zzaW", U3.h, "zzax", U3.f, "zzaI", "zzaP", "zzbd", "zzbe", "zzbf"});
        }
        if (iK == 3) {
            return new C2384n4();
        }
        if (iK == 4) {
            return new C1864b4(zza);
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
        synchronized (C2384n4.class) {
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
