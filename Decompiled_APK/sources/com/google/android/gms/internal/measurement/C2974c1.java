package com.google.android.gms.internal.measurement;

import android.os.Build;
import com.amazon.device.ads.DtbConstants;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.ArrayList;
import java.util.RandomAccess;
import java.util.Set;

/* renamed from: com.google.android.gms.internal.measurement.c1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2974c1 extends W1 {
    private static final C2974c1 zzb;
    private long zzA;
    private int zzB;
    private String zzC;
    private String zzD;
    private boolean zzE;
    private InterfaceC2975c2 zzF;
    private String zzG;
    private int zzH;
    private int zzI;
    private int zzJ;
    private String zzK;
    private long zzL;
    private long zzM;
    private String zzN;
    private String zzO;
    private int zzP;
    private String zzQ;
    private C2979d1 zzR;
    private InterfaceC2965a2 zzS;
    private long zzT;
    private long zzU;
    private String zzV;
    private String zzW;
    private int zzX;
    private boolean zzY;
    private String zzZ;
    private boolean zzaa;
    private Y0 zzab;
    private String zzac;
    private InterfaceC2975c2 zzad;
    private String zzae;
    private long zzaf;
    private boolean zzag;
    private String zzah;
    private boolean zzai;
    private String zzaj;
    private int zzak;
    private String zzal;
    private O0 zzam;
    private int zzan;
    private L0 zzao;
    private String zzap;
    private C3009j1 zzaq;
    private long zzar;
    private String zzas;
    private int zzd;
    private int zze;
    private int zzf;
    private InterfaceC2975c2 zzg;
    private InterfaceC2975c2 zzh;
    private long zzi;
    private long zzj;
    private long zzk;
    private long zzl;
    private long zzm;
    private String zzn;
    private String zzo;
    private String zzp;
    private String zzq;
    private int zzr;
    private String zzs;
    private String zzt;
    private String zzu;
    private long zzv;
    private long zzw;
    private String zzx;
    private boolean zzy;
    private String zzz;

    static {
        C2974c1 c2974c1 = new C2974c1();
        zzb = c2974c1;
        W1.j(C2974c1.class, c2974c1);
    }

    public C2974c1() {
        C3059t2 c3059t2 = C3059t2.e;
        this.zzg = c3059t2;
        this.zzh = c3059t2;
        this.zzn = "";
        this.zzo = "";
        this.zzp = "";
        this.zzq = "";
        this.zzs = "";
        this.zzt = "";
        this.zzu = "";
        this.zzx = "";
        this.zzz = "";
        this.zzC = "";
        this.zzD = "";
        this.zzF = c3059t2;
        this.zzG = "";
        this.zzK = "";
        this.zzN = "";
        this.zzO = "";
        this.zzQ = "";
        this.zzS = X1.e;
        this.zzV = "";
        this.zzW = "";
        this.zzZ = "";
        this.zzac = "";
        this.zzad = c3059t2;
        this.zzae = "";
        this.zzah = "";
        this.zzaj = "";
        this.zzal = "";
        this.zzap = "";
        this.zzas = "";
    }

    public static /* synthetic */ void A0(C2974c1 c2974c1) {
        c2974c1.zzd &= -17;
        c2974c1.zzl = 0L;
    }

    public static /* synthetic */ void A1(C2974c1 c2974c1, int i) {
        c2974c1.zzd |= 1024;
        c2974c1.zzr = i;
    }

    public static /* synthetic */ void B0(C2974c1 c2974c1) {
        c2974c1.zzd &= -65537;
        c2974c1.zzx = zzb.zzx;
    }

    public static /* synthetic */ void B1(C2974c1 c2974c1, long j) {
        c2974c1.zzd |= 2;
        c2974c1.zzi = j;
    }

    public static /* synthetic */ void C0(C2974c1 c2974c1) {
        c2974c1.zze &= -8193;
        c2974c1.zzac = zzb.zzac;
    }

    public static /* synthetic */ void C1(C2974c1 c2974c1) {
        c2974c1.zzd |= 32768;
        c2974c1.zzw = 119002L;
    }

    public static /* synthetic */ void D0(C2974c1 c2974c1) {
        c2974c1.zzd &= -268435457;
        c2974c1.zzK = zzb.zzK;
    }

    public static /* synthetic */ void D1(C2974c1 c2974c1, int i, C3019l1 c3019l1) {
        c2974c1.O1();
        c2974c1.zzh.set(i, c3019l1);
    }

    public static /* synthetic */ void E0(C2974c1 c2974c1) {
        c2974c1.zzd &= -3;
        c2974c1.zzi = 0L;
    }

    public static /* synthetic */ void E1(C2974c1 c2974c1, String str) {
        str.getClass();
        c2974c1.zzd |= com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH;
        c2974c1.zzq = str;
    }

    public static /* synthetic */ void F0(C2974c1 c2974c1, int i) {
        c2974c1.N1();
        c2974c1.zzg.remove(i);
    }

    public static /* synthetic */ void G0(C2974c1 c2974c1, int i) {
        c2974c1.O1();
        c2974c1.zzh.remove(i);
    }

    public static /* synthetic */ void H0(C2974c1 c2974c1, L0 l0) {
        c2974c1.zzao = l0;
        c2974c1.zze |= 16777216;
    }

    public static /* synthetic */ void I0(C2974c1 c2974c1, int i) {
        c2974c1.zze |= 1048576;
        c2974c1.zzak = i;
    }

    public static /* synthetic */ void J0(C2974c1 c2974c1, String str) {
        str.getClass();
        c2974c1.zze |= 4;
        c2974c1.zzQ = str;
    }

    public static /* synthetic */ void K0(C2974c1 c2974c1, String str) {
        str.getClass();
        c2974c1.zzd |= 4096;
        c2974c1.zzt = str;
    }

    public static void L(C2974c1 c2974c1, ArrayList arrayList) {
        InterfaceC2975c2 interfaceC2975c2 = c2974c1.zzF;
        if (!((K1) interfaceC2975c2).a) {
            int size = interfaceC2975c2.size();
            c2974c1.zzF = interfaceC2975c2.f(size + size);
        }
        J1.b(arrayList, c2974c1.zzF);
    }

    public static /* synthetic */ void L0(C2974c1 c2974c1, String str) {
        c2974c1.zzd |= 262144;
        c2974c1.zzz = str;
    }

    public static /* synthetic */ void N(C2974c1 c2974c1, String str) {
        str.getClass();
        c2974c1.zzd |= 2048;
        c2974c1.zzs = str;
    }

    public static /* synthetic */ void O(C2974c1 c2974c1, String str) {
        str.getClass();
        c2974c1.zzd |= 8192;
        c2974c1.zzu = str;
    }

    public static /* synthetic */ void P(C2974c1 c2974c1, int i) {
        c2974c1.zzd |= 33554432;
        c2974c1.zzH = i;
    }

    public static /* synthetic */ void Q(C2974c1 c2974c1, O0 o0) {
        c2974c1.zzam = o0;
        c2974c1.zze |= 4194304;
    }

    public static /* synthetic */ void R(C2974c1 c2974c1, long j) {
        c2974c1.zze |= 134217728;
        c2974c1.zzar = j;
    }

    public static /* synthetic */ void S(C2974c1 c2974c1, int i) {
        c2974c1.zzd |= 1048576;
        c2974c1.zzB = i;
    }

    public static /* synthetic */ void T(C2974c1 c2974c1, long j) {
        c2974c1.zze |= 32;
        c2974c1.zzU = j;
    }

    public static /* synthetic */ void U(C2974c1 c2974c1, long j) {
        c2974c1.zzd |= 536870912;
        c2974c1.zzL = j;
    }

    public static /* synthetic */ void V(C2974c1 c2974c1, String str) {
        c2974c1.zze |= 131072;
        c2974c1.zzah = str;
    }

    public static /* synthetic */ void W(C2974c1 c2974c1, String str) {
        c2974c1.zze |= 128;
        c2974c1.zzW = str;
    }

    public static /* synthetic */ void X(C2974c1 c2974c1, String str) {
        str.getClass();
        c2974c1.zze |= 524288;
        c2974c1.zzaj = str;
    }

    public static /* synthetic */ void Y(C2974c1 c2974c1, int i) {
        c2974c1.zze |= 8388608;
        c2974c1.zzan = i;
    }

    public static /* synthetic */ void Z(C2974c1 c2974c1, long j) {
        c2974c1.zzd |= 524288;
        c2974c1.zzA = j;
    }

    public static /* synthetic */ void a0(C2974c1 c2974c1) {
        String str = Build.MODEL;
        str.getClass();
        c2974c1.zzd |= 256;
        c2974c1.zzp = str;
    }

    public static /* synthetic */ void b0(C2974c1 c2974c1, String str) {
        str.getClass();
        c2974c1.zzd |= Integer.MIN_VALUE;
        c2974c1.zzN = str;
    }

    public static /* synthetic */ void c0(C2974c1 c2974c1, long j) {
        c2974c1.zze |= 16;
        c2974c1.zzT = j;
    }

    public static /* synthetic */ void d0(C2974c1 c2974c1, boolean z) {
        c2974c1.zze |= 65536;
        c2974c1.zzag = z;
    }

    public static /* synthetic */ void e0(C2974c1 c2974c1, long j) {
        c2974c1.zzd |= 8;
        c2974c1.zzk = j;
    }

    public static /* synthetic */ void f0(C2974c1 c2974c1, String str) {
        str.getClass();
        c2974c1.zze |= 16384;
        c2974c1.zzae = str;
    }

    public static /* synthetic */ void g0(C2974c1 c2974c1, int i, U0 u0) {
        c2974c1.N1();
        c2974c1.zzg.set(i, u0);
    }

    public static /* synthetic */ void h0(C2974c1 c2974c1) {
        c2974c1.zze |= 268435456;
        c2974c1.zzas = "";
    }

    public static /* synthetic */ void i0(C2974c1 c2974c1, String str) {
        c2974c1.zzd |= 16777216;
        c2974c1.zzG = str;
    }

    public static /* synthetic */ void j0(C2974c1 c2974c1, String str) {
        str.getClass();
        c2974c1.zzd |= 4194304;
        c2974c1.zzD = str;
    }

    public static /* synthetic */ void k0(C2974c1 c2974c1, long j) {
        c2974c1.zzd |= 16384;
        c2974c1.zzv = j;
    }

    public static C2969b1 k2() {
        return (C2969b1) zzb.e();
    }

    public static /* synthetic */ void l0(C2974c1 c2974c1, String str) {
        c2974c1.zzd |= 2097152;
        c2974c1.zzC = str;
    }

    public static /* synthetic */ void m0(C2974c1 c2974c1, boolean z) {
        c2974c1.zze |= 262144;
        c2974c1.zzai = z;
    }

    public static C2969b1 n(C2974c1 c2974c1) {
        V1 v1E = zzb.e();
        v1E.d(c2974c1);
        return (C2969b1) v1E;
    }

    public static /* synthetic */ void n0(C2974c1 c2974c1, ArrayList arrayList) {
        c2974c1.N1();
        J1.b(arrayList, c2974c1.zzg);
    }

    public static /* synthetic */ void n1(C2974c1 c2974c1, boolean z) {
        c2974c1.zzd |= 131072;
        c2974c1.zzy = z;
    }

    public static void o0(C2974c1 c2974c1, ArrayList arrayList) {
        RandomAccess randomAccess = c2974c1.zzS;
        if (!((K1) randomAccess).a) {
            X1 x1 = (X1) randomAccess;
            int i = x1.c;
            c2974c1.zzS = x1.f(i + i);
        }
        J1.b(arrayList, c2974c1.zzS);
    }

    public static /* synthetic */ void o1(C2974c1 c2974c1, String str) {
        str.getClass();
        c2974c1.zzd |= 128;
        c2974c1.zzo = str;
    }

    public static void p0(C2974c1 c2974c1, Set set) {
        InterfaceC2975c2 interfaceC2975c2 = c2974c1.zzad;
        if (!((K1) interfaceC2975c2).a) {
            int size = interfaceC2975c2.size();
            c2974c1.zzad = interfaceC2975c2.f(size + size);
        }
        J1.b(set, c2974c1.zzad);
    }

    public static /* synthetic */ void p1(C2974c1 c2974c1) {
        c2974c1.zzd |= 64;
        c2974c1.zzn = DtbConstants.NATIVE_OS_NAME;
    }

    public static /* synthetic */ void q0(C2974c1 c2974c1, U0 u0) {
        c2974c1.N1();
        c2974c1.zzg.add(u0);
    }

    public static /* synthetic */ void q1(C2974c1 c2974c1, long j) {
        c2974c1.zzd |= 32;
        c2974c1.zzm = j;
    }

    public static /* synthetic */ void r0(C2974c1 c2974c1, C3019l1 c3019l1) {
        c2974c1.O1();
        c2974c1.zzh.add(c3019l1);
    }

    public static /* synthetic */ void r1(C2974c1 c2974c1, long j) {
        c2974c1.zzd |= 16;
        c2974c1.zzl = j;
    }

    public static /* synthetic */ void s0(C2974c1 c2974c1) {
        c2974c1.zzd &= -262145;
        c2974c1.zzz = zzb.zzz;
    }

    public static /* synthetic */ void s1(C2974c1 c2974c1) {
        c2974c1.zzd |= 1;
        c2974c1.zzf = 1;
    }

    public static void t0(C2974c1 c2974c1) {
        c2974c1.zzF = C3059t2.e;
    }

    public static /* synthetic */ void t1(C2974c1 c2974c1, String str) {
        str.getClass();
        c2974c1.zzd |= 65536;
        c2974c1.zzx = str;
    }

    public static /* synthetic */ void u0(C2974c1 c2974c1) {
        c2974c1.zzd &= -257;
        c2974c1.zzp = zzb.zzp;
    }

    public static /* synthetic */ void u1(C2974c1 c2974c1, int i) {
        c2974c1.zze |= 2;
        c2974c1.zzP = i;
    }

    public static /* synthetic */ void v0(C2974c1 c2974c1) {
        c2974c1.zzd &= SubsamplingScaleImageView.TILE_SIZE_AUTO;
        c2974c1.zzN = zzb.zzN;
    }

    public static /* synthetic */ void v1(C2974c1 c2974c1) {
        c2974c1.zzd |= 8388608;
        c2974c1.zzE = false;
    }

    public static void w0(C2974c1 c2974c1) {
        c2974c1.zzg = C3059t2.e;
    }

    public static /* synthetic */ void w1(C2974c1 c2974c1, String str) {
        str.getClass();
        c2974c1.zze |= 8192;
        c2974c1.zzac = str;
    }

    public static /* synthetic */ void x0(C2974c1 c2974c1) {
        c2974c1.zzd &= -2097153;
        c2974c1.zzC = zzb.zzC;
    }

    public static /* synthetic */ void x1(C2974c1 c2974c1, C3009j1 c3009j1) {
        c2974c1.zzaq = c3009j1;
        c2974c1.zze |= 67108864;
    }

    public static /* synthetic */ void y0(C2974c1 c2974c1) {
        c2974c1.zzd &= -131073;
        c2974c1.zzy = false;
    }

    public static /* synthetic */ void y1(C2974c1 c2974c1, long j) {
        c2974c1.zzd |= 4;
        c2974c1.zzj = j;
    }

    public static /* synthetic */ void z0(C2974c1 c2974c1) {
        c2974c1.zzd &= -33;
        c2974c1.zzm = 0L;
    }

    public static /* synthetic */ void z1(C2974c1 c2974c1, long j) {
        c2974c1.zze |= 32768;
        c2974c1.zzaf = j;
    }

    public final String A() {
        return this.zzG;
    }

    public final String B() {
        return this.zzD;
    }

    public final String C() {
        return this.zzC;
    }

    public final String D() {
        return this.zzo;
    }

    public final String E() {
        return this.zzn;
    }

    public final String F() {
        return this.zzx;
    }

    public final boolean F1() {
        return this.zzag;
    }

    public final String G() {
        return this.zzac;
    }

    public final boolean G1() {
        return this.zzai;
    }

    public final String H() {
        return this.zzq;
    }

    public final boolean H1() {
        return this.zzy;
    }

    public final InterfaceC2975c2 I() {
        return this.zzF;
    }

    public final boolean I1() {
        return this.zzE;
    }

    public final InterfaceC2975c2 J() {
        return this.zzg;
    }

    public final boolean J1() {
        return (this.zze & 16777216) != 0;
    }

    public final InterfaceC2975c2 K() {
        return this.zzh;
    }

    public final boolean K1() {
        return (this.zzd & 33554432) != 0;
    }

    public final boolean L1() {
        return (this.zze & 4194304) != 0;
    }

    public final int M() {
        return this.zzak;
    }

    public final int M0() {
        return this.zzH;
    }

    public final int M1() {
        return this.zzB;
    }

    public final boolean N0() {
        return (this.zze & 134217728) != 0;
    }

    public final void N1() {
        InterfaceC2975c2 interfaceC2975c2 = this.zzg;
        if (((K1) interfaceC2975c2).a) {
            return;
        }
        int size = interfaceC2975c2.size();
        this.zzg = interfaceC2975c2.f(size + size);
    }

    public final boolean O0() {
        return (this.zzd & 1048576) != 0;
    }

    public final void O1() {
        InterfaceC2975c2 interfaceC2975c2 = this.zzh;
        if (((K1) interfaceC2975c2).a) {
            return;
        }
        int size = interfaceC2975c2.size();
        this.zzh = interfaceC2975c2.f(size + size);
    }

    public final boolean P0() {
        return (this.zzd & 536870912) != 0;
    }

    public final int P1() {
        return this.zzan;
    }

    public final boolean Q0() {
        return (this.zze & 131072) != 0;
    }

    public final int Q1() {
        return this.zzg.size();
    }

    public final boolean R0() {
        return (this.zze & 128) != 0;
    }

    public final int R1() {
        return this.zzf;
    }

    public final boolean S0() {
        return (this.zze & 524288) != 0;
    }

    public final int S1() {
        return this.zzP;
    }

    public final boolean T0() {
        return (this.zze & 8388608) != 0;
    }

    public final int T1() {
        return this.zzr;
    }

    public final boolean U0() {
        return (this.zzd & 524288) != 0;
    }

    public final int U1() {
        return this.zzh.size();
    }

    public final boolean V0() {
        return (this.zzd & Integer.MIN_VALUE) != 0;
    }

    public final long V1() {
        return this.zzar;
    }

    public final boolean W0() {
        return (this.zze & 16) != 0;
    }

    public final long W1() {
        return this.zzL;
    }

    public final boolean X0() {
        return (this.zzd & 8) != 0;
    }

    public final long X1() {
        return this.zzA;
    }

    public final boolean Y0() {
        return (this.zzd & 16384) != 0;
    }

    public final long Y1() {
        return this.zzT;
    }

    public final boolean Z0() {
        return (this.zze & 262144) != 0;
    }

    public final long Z1() {
        return this.zzk;
    }

    public final boolean a1() {
        return (this.zzd & 131072) != 0;
    }

    public final long a2() {
        return this.zzv;
    }

    public final boolean b1() {
        return (this.zzd & 32) != 0;
    }

    public final long b2() {
        return this.zzm;
    }

    public final boolean c1() {
        return (this.zzd & 16) != 0;
    }

    public final long c2() {
        return this.zzl;
    }

    public final boolean d1() {
        return (this.zzd & 1) != 0;
    }

    public final long d2() {
        return this.zzj;
    }

    public final boolean e1() {
        return (this.zze & 2) != 0;
    }

    public final long e2() {
        return this.zzaf;
    }

    public final boolean f1() {
        return (this.zzd & 8388608) != 0;
    }

    public final long f2() {
        return this.zzi;
    }

    public final boolean g1() {
        return (this.zze & 8192) != 0;
    }

    public final long g2() {
        return this.zzw;
    }

    public final boolean h1() {
        return (this.zze & 67108864) != 0;
    }

    public final L0 h2() {
        L0 l0 = this.zzao;
        return l0 == null ? L0.y() : l0;
    }

    public final boolean i1() {
        return (this.zzd & 4) != 0;
    }

    public final O0 i2() {
        O0 o0 = this.zzam;
        return o0 == null ? O0.o() : o0;
    }

    public final boolean j1() {
        return (this.zze & 32768) != 0;
    }

    public final U0 j2(int i) {
        return (U0) this.zzg.get(i);
    }

    public final boolean k1() {
        return (this.zzd & 1024) != 0;
    }

    public final boolean l1() {
        return (this.zzd & 2) != 0;
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004B\u0000\u0002\u0001SB\u0000\u0005\u0000\u0001င\u0000\u0002\u001b\u0003\u001b\u0004ဂ\u0001\u0005ဂ\u0002\u0006ဂ\u0003\u0007ဂ\u0005\bဈ\u0006\tဈ\u0007\nဈ\b\u000bဈ\t\fင\n\rဈ\u000b\u000eဈ\f\u0010ဈ\r\u0011ဂ\u000e\u0012ဂ\u000f\u0013ဈ\u0010\u0014ဇ\u0011\u0015ဈ\u0012\u0016ဂ\u0013\u0017င\u0014\u0018ဈ\u0015\u0019ဈ\u0016\u001aဂ\u0004\u001cဇ\u0017\u001d\u001b\u001eဈ\u0018\u001fင\u0019 င\u001a!င\u001b\"ဈ\u001c#ဂ\u001d$ဂ\u001e%ဈ\u001f&ဈ 'င!)ဈ\",ဉ#-\u001d.ဂ$/ဂ%2ဈ&4ဈ'5᠌(7ဇ)9ဈ*:ဇ+;ဉ,?ဈ-@\u001aAဈ.Cဂ/Dဇ0Gဈ1Hဇ2Iဈ3Jင4Kဈ5Lဉ6Mင7Oဉ8Pဈ9Qဉ:Rဂ;Sဈ<", new Object[]{"zzd", "zze", "zzf", "zzg", U0.class, "zzh", C3019l1.class, "zzi", "zzj", "zzk", "zzm", "zzn", "zzo", "zzp", "zzq", "zzr", "zzs", "zzt", "zzu", "zzv", "zzw", "zzx", "zzy", "zzz", "zzA", "zzB", "zzC", "zzD", "zzl", "zzE", "zzF", Q0.class, "zzG", "zzH", "zzI", "zzJ", "zzK", "zzL", "zzM", "zzN", "zzO", "zzP", "zzQ", "zzR", "zzS", "zzT", "zzU", "zzV", "zzW", "zzX", C3047r0.f, "zzY", "zzZ", "zzaa", "zzab", "zzac", "zzad", "zzae", "zzaf", "zzag", "zzah", "zzai", "zzaj", "zzak", "zzal", "zzam", "zzan", "zzao", "zzap", "zzaq", "zzar", "zzas"});
        }
        if (i2 == 3) {
            return new C2974c1();
        }
        if (i2 == 4) {
            return new C2969b1(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final boolean m1() {
        return (this.zzd & 32768) != 0;
    }

    public final C3009j1 o() {
        C3009j1 c3009j1 = this.zzaq;
        return c3009j1 == null ? C3009j1.p() : c3009j1;
    }

    public final C3019l1 p(int i) {
        return (C3019l1) this.zzh.get(i);
    }

    public final String q() {
        return this.zzQ;
    }

    public final String r() {
        return this.zzt;
    }

    public final String s() {
        return this.zzz;
    }

    public final String t() {
        return this.zzs;
    }

    public final String u() {
        return this.zzu;
    }

    public final String v() {
        return this.zzah;
    }

    public final String w() {
        return this.zzW;
    }

    public final String x() {
        return this.zzaj;
    }

    public final String y() {
        return this.zzp;
    }

    public final String z() {
        return this.zzN;
    }
}
