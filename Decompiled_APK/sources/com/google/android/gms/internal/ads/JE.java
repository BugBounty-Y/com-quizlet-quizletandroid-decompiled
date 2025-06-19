package com.google.android.gms.internal.ads;

import android.media.MediaCodec;
import android.media.MediaFormat;
import android.os.Bundle;
import android.os.SystemClock;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Objects;

/* loaded from: classes2.dex */
public abstract class JE implements ID {
    public final ArrayDeque A;
    public long A1;
    public final C2338m1 B;
    public boolean B1;
    public C1832aG C;
    public boolean C1;
    public C1832aG D;
    public C2883yp D1;
    public C2307lD E;
    public C2883yp E1;
    public final long F;
    public float G;
    public float H;
    public GE I;
    public C1832aG J;
    public MediaFormat K;
    public boolean L;
    public float M;
    public ArrayDeque V;
    public zztf W;
    public HE X;
    public boolean Y;
    public boolean Z;
    public final Object a;
    public final int b;
    public final Ps c;
    public long c1;
    public MD d;
    public long d1;
    public int e;
    public int e1;
    public C1917cE f;
    public int f1;
    public C1847ao g;
    public ByteBuffer g1;
    public int h;
    public boolean h1;
    public AF i;
    public boolean i1;
    public C1832aG[] j;
    public boolean j1;
    public long k;
    public boolean k1;
    public long l;
    public boolean l1;
    public long m;
    public boolean m1;
    public boolean n;
    public int n1;
    public boolean o;
    public int o1;
    public A9 p;
    public int p1;
    public C2093gF q;
    public boolean q1;
    public VF r;
    public boolean r1;
    public final Wr s;
    public boolean s1;
    public final C1 t;
    public long t1;
    public final float u;
    public long u1;
    public final MC v;
    public boolean v1;
    public final MC w;
    public boolean w1;
    public final MC x;
    public boolean x1;
    public final EE y;
    public QC y1;
    public final MediaCodec.BufferInfo z;
    public IE z1;

    public JE(int i, Wr wr, float f) {
        C1 c1 = C1.n;
        this.a = new Object();
        this.b = i;
        this.c = new Ps();
        this.m = Long.MIN_VALUE;
        this.p = A9.a;
        this.s = wr;
        this.t = c1;
        this.u = f;
        this.v = new MC(0);
        this.w = new MC(0);
        this.x = new MC(2);
        EE ee = new EE(2);
        ee.l = 32;
        this.y = ee;
        this.z = new MediaCodec.BufferInfo();
        this.G = 1.0f;
        this.H = 1.0f;
        this.F = -9223372036854775807L;
        this.A = new ArrayDeque();
        this.z1 = IE.e;
        ee.w(0);
        ee.e.order(ByteOrder.nativeOrder());
        C2338m1 c2338m1 = new C2338m1();
        c2338m1.c = InterfaceC1688Ef.a;
        c2338m1.b = 0;
        c2338m1.a = 2;
        this.B = c2338m1;
        this.M = -1.0f;
        this.n1 = 0;
        this.e1 = -1;
        this.f1 = -1;
        this.d1 = -9223372036854775807L;
        this.t1 = -9223372036854775807L;
        this.u1 = -9223372036854775807L;
        this.A1 = -9223372036854775807L;
        this.c1 = -9223372036854775807L;
        this.o1 = 0;
        this.p1 = 0;
        this.y1 = new QC();
    }

    public void A(C1832aG c1832aG) {
    }

    public boolean B(MC mc) {
        return false;
    }

    public boolean C(HE he) {
        return true;
    }

    public final void D(IE ie) {
        this.z1 = ie;
        if (ie.c != -9223372036854775807L) {
            this.B1 = true;
        }
    }

    public final boolean E() {
        if (this.q1) {
            this.o1 = 1;
            this.p1 = 2;
            return true;
        }
        C2883yp c2883yp = this.E1;
        c2883yp.getClass();
        this.D1 = c2883yp;
        this.o1 = 0;
        this.p1 = 0;
        return true;
    }

    public final boolean F(long j, long j2) {
        if (j2 >= j) {
            return false;
        }
        C1832aG c1832aG = this.D;
        return c1832aG == null || !Objects.equals(c1832aG.m, "audio/opus") || j - j2 > 80000;
    }

    public final boolean G(int i) throws Throwable {
        Ps ps = this.c;
        ps.b = null;
        ps.a = null;
        MC mc = this.v;
        mc.v();
        int iA0 = a0(ps, mc, i | 4);
        if (iA0 == -5) {
            K(ps);
            return true;
        }
        if (iA0 != -4 || !mc.s(4)) {
            return false;
        }
        this.v1 = true;
        Q();
        return false;
    }

    public final boolean H(C1832aG c1832aG) throws Throwable {
        if (this.I != null && this.p1 != 3 && this.h != 0) {
            float f = this.H;
            c1832aG.getClass();
            C1832aG[] c1832aGArr = this.j;
            c1832aGArr.getClass();
            float fR = r(f, c1832aGArr);
            float f2 = this.M;
            if (f2 != fR) {
                if (fR == -1.0f) {
                    M();
                    return false;
                }
                if (f2 != -1.0f || fR > this.u) {
                    Bundle bundle = new Bundle();
                    bundle.putFloat("operating-rate", fR);
                    GE ge = this.I;
                    ge.getClass();
                    ge.o(bundle);
                    this.M = fR;
                }
            }
        }
        return true;
    }

    public abstract int I(C1 c1, C1832aG c1832aG);

    public abstract RC J(HE he, C1832aG c1832aG, C1832aG c1832aG2);

    public RC K(Ps ps) throws Throwable {
        int i;
        this.x1 = true;
        C1832aG c1832aG = (C1832aG) ps.a;
        c1832aG.getClass();
        String str = c1832aG.m;
        if (str == null) {
            throw b0(new IllegalArgumentException("Sample MIME type is null."), c1832aG, false, 4005);
        }
        if (str.equals("video/av01") && !c1832aG.p.isEmpty()) {
            EF ef = new EF(c1832aG);
            ef.o = null;
            c1832aG = new C1832aG(ef);
        }
        C1832aG c1832aG2 = c1832aG;
        this.E1 = (C2883yp) ps.b;
        this.C = c1832aG2;
        if (this.j1) {
            this.l1 = true;
            return null;
        }
        GE ge = this.I;
        if (ge == null) {
            this.V = null;
            t();
            return null;
        }
        HE he = this.X;
        he.getClass();
        C1832aG c1832aG3 = this.J;
        c1832aG3.getClass();
        C2883yp c2883yp = this.D1;
        C2883yp c2883yp2 = this.E1;
        if (c2883yp != c2883yp2) {
            M();
            return new RC(he.a, c1832aG3, c1832aG2, 0, 128);
        }
        boolean z = c2883yp2 != c2883yp;
        RC rcJ = J(he, c1832aG3, c1832aG2);
        int i2 = rcJ.d;
        if (i2 != 0) {
            if (i2 == 1) {
                if (H(c1832aG2)) {
                    this.J = c1832aG2;
                    if (z) {
                        E();
                    } else if (this.q1) {
                        this.o1 = 1;
                        this.p1 = 1;
                    }
                }
                i = 16;
            } else if (i2 != 2) {
                if (H(c1832aG2)) {
                    this.J = c1832aG2;
                    if (z) {
                        E();
                    }
                }
                i = 16;
            } else {
                if (H(c1832aG2)) {
                    this.m1 = true;
                    this.n1 = 1;
                    this.J = c1832aG2;
                    if (z) {
                        E();
                    }
                }
                i = 16;
            }
            return (i2 != 0 || (this.I == ge && this.p1 != 3)) ? rcJ : new RC(he.a, c1832aG3, c1832aG2, 0, i);
        }
        M();
        i = 0;
        if (i2 != 0) {
        }
    }

    public final void L() {
        this.l1 = false;
        this.y.v();
        this.x.v();
        this.k1 = false;
        this.j1 = false;
        C2338m1 c2338m1 = this.B;
        c2338m1.getClass();
        c2338m1.c = InterfaceC1688Ef.a;
        c2338m1.b = 0;
        c2338m1.a = 2;
    }

    public final void M() throws Throwable {
        if (this.q1) {
            this.o1 = 1;
            this.p1 = 3;
        } else {
            w();
            t();
        }
    }

    public abstract com.quizlet.data.interactor.folderwithcreator.m N(HE he, C1832aG c1832aG, float f);

    public abstract ArrayList O(C1 c1, C1832aG c1832aG);

    public final void P() {
        try {
            GE ge = this.I;
            AbstractC1795We.p(ge);
            ge.i();
        } finally {
            x();
        }
    }

    public final void Q() throws Throwable {
        int i = this.p1;
        if (i == 1) {
            P();
            return;
        }
        if (i != 2) {
            if (i != 3) {
                this.w1 = true;
                X();
                return;
            } else {
                w();
                t();
                return;
            }
        }
        P();
        C2883yp c2883yp = this.E1;
        c2883yp.getClass();
        this.D1 = c2883yp;
        this.o1 = 0;
        this.p1 = 0;
    }

    public abstract void R(MC mc);

    public abstract void S(Exception exc);

    public abstract void T(long j, long j2, String str);

    public abstract void U(String str);

    public abstract void V(C1832aG c1832aG, MediaFormat mediaFormat);

    public abstract void W();

    public abstract void X();

    public abstract boolean Y(long j, long j2, GE ge, ByteBuffer byteBuffer, int i, int i2, int i3, long j3, boolean z, boolean z2, C1832aG c1832aG);

    public boolean Z(C1832aG c1832aG) {
        return false;
    }

    public final int a0(Ps ps, MC mc, int i) {
        AF af = this.i;
        af.getClass();
        int iB = af.b(ps, mc, i);
        if (iB == -4) {
            if (mc.s(4)) {
                this.m = Long.MIN_VALUE;
                return this.n ? -4 : -3;
            }
            long j = mc.g + this.k;
            mc.g = j;
            this.m = Math.max(this.m, j);
            return iB;
        }
        if (iB == -5) {
            C1832aG c1832aG = (C1832aG) ps.a;
            c1832aG.getClass();
            long j2 = c1832aG.r;
            if (j2 != Long.MAX_VALUE) {
                EF ef = new EF(c1832aG);
                ef.q = j2 + this.k;
                ps.a = new C1832aG(ef);
                return -5;
            }
        }
        return iB;
    }

    public final zzik b0(Exception exc, C1832aG c1832aG, boolean z, int i) {
        int iQ;
        if (c1832aG == null || this.o) {
            iQ = 4;
        } else {
            this.o = true;
            try {
                iQ = q(c1832aG) & 7;
            } catch (zzik unused) {
            } finally {
                this.o = false;
            }
        }
        return new zzik(1, exc, i, m(), this.e, c1832aG, c1832aG == null ? 4 : iQ, this.q, z);
    }

    public final C1847ao c0() {
        C1847ao c1847ao = this.g;
        c1847ao.getClass();
        return c1847ao;
    }

    public abstract void d();

    public InterfaceC2650tD d0() {
        return null;
    }

    public abstract void e();

    public final void e0() {
        this.d.getClass();
    }

    public abstract void f();

    public final void f0() {
        synchronized (this.a) {
            this.r = null;
        }
    }

    public abstract void g();

    public void g0() {
    }

    /* JADX WARN: Code restructure failed: missing block: B:15:0x003a, code lost:
    
        if (r4 >= r0) goto L16;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void h(com.google.android.gms.internal.ads.C1832aG[] r12, long r13, long r15, com.google.android.gms.internal.ads.C2093gF r17) {
        /*
            r11 = this;
            com.google.android.gms.internal.ads.IE r12 = r11.z1
            long r0 = r12.c
            r2 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
            int r12 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r12 != 0) goto L24
            com.google.android.gms.internal.ads.IE r4 = new com.google.android.gms.internal.ads.IE
            r5 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
            r7 = r13
            r9 = r15
            r4.<init>(r5, r7, r9)
            r11.D(r4)
            boolean r12 = r11.C1
            if (r12 == 0) goto L56
            r11.W()
            return
        L24:
            java.util.ArrayDeque r12 = r11.A
            boolean r0 = r12.isEmpty()
            if (r0 == 0) goto L57
            long r0 = r11.t1
            int r4 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r4 == 0) goto L3c
            long r4 = r11.A1
            int r6 = (r4 > r2 ? 1 : (r4 == r2 ? 0 : -1))
            if (r6 == 0) goto L57
            int r0 = (r4 > r0 ? 1 : (r4 == r0 ? 0 : -1))
            if (r0 < 0) goto L57
        L3c:
            com.google.android.gms.internal.ads.IE r4 = new com.google.android.gms.internal.ads.IE
            r5 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
            r7 = r13
            r9 = r15
            r4.<init>(r5, r7, r9)
            r11.D(r4)
            com.google.android.gms.internal.ads.IE r12 = r11.z1
            long r12 = r12.c
            int r12 = (r12 > r2 ? 1 : (r12 == r2 ? 0 : -1))
            if (r12 == 0) goto L56
            r11.W()
        L56:
            return
        L57:
            com.google.android.gms.internal.ads.IE r0 = new com.google.android.gms.internal.ads.IE
            long r1 = r11.t1
            r3 = r13
            r5 = r15
            r0.<init>(r1, r3, r5)
            r12.add(r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.JE.h(com.google.android.gms.internal.ads.aG[], long, long, com.google.android.gms.internal.ads.gF):void");
    }

    public void h0() {
        this.C = null;
        D(IE.e);
        this.A.clear();
        z();
    }

    public abstract void i0(boolean z, boolean z2);

    public final void j(C1832aG[] c1832aGArr, AF af, long j, long j2, C2093gF c2093gF) {
        AbstractC1795We.L(!this.n);
        this.i = af;
        this.q = c2093gF;
        if (this.m == Long.MIN_VALUE) {
            this.m = j;
        }
        this.j = c1832aGArr;
        this.k = j2;
        h(c1832aGArr, j, j2, c2093gF);
    }

    public void j0(long j, boolean z) {
        this.v1 = false;
        this.w1 = false;
        if (this.j1) {
            this.y.v();
            this.x.v();
            this.k1 = false;
            C2338m1 c2338m1 = this.B;
            c2338m1.getClass();
            c2338m1.c = InterfaceC1688Ef.a;
            c2338m1.b = 0;
            c2338m1.a = 2;
        } else if (z()) {
            t();
        }
        androidx.compose.ui.text.android.selection.f fVar = this.z1.d;
        if (fVar.o() > 0) {
            this.x1 = true;
        }
        synchronized (fVar) {
            fVar.b = 0;
            fVar.c = 0;
            Arrays.fill((Object[]) fVar.e, (Object) null);
        }
        this.A.clear();
    }

    public void k(float f, float f2) {
        this.G = f;
        this.H = f2;
        H(this.J);
    }

    public final boolean l() {
        return this.m == Long.MIN_VALUE;
    }

    public abstract String m();

    /* JADX WARN: Code restructure failed: missing block: B:165:0x02a6, code lost:
    
        r13 = r2;
        r29 = r7;
        r3 = -1;
        r28 = r12;
        r9 = r20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:205:0x0335, code lost:
    
        throw r27;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x0088, code lost:
    
        r6 = false;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:107:0x01d1  */
    /* JADX WARN: Removed duplicated region for block: B:110:0x01db  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x01dc A[Catch: IllegalStateException -> 0x00ac, CryptoException -> 0x00b0, TryCatch #0 {CryptoException -> 0x00b0, blocks: (B:129:0x0226, B:45:0x00a9, B:55:0x00bb, B:57:0x00bf, B:59:0x00c5, B:63:0x00df, B:64:0x00ee, B:68:0x00fb, B:70:0x0101, B:119:0x0205, B:121:0x020b, B:122:0x020e, B:124:0x0214, B:126:0x0218, B:72:0x010f, B:74:0x0116, B:75:0x0126, B:77:0x0136, B:81:0x0145, B:82:0x0147, B:85:0x014d, B:87:0x0151, B:89:0x015b, B:91:0x0165, B:92:0x018d, B:93:0x0195, B:94:0x0196, B:96:0x019d, B:98:0x01a5, B:100:0x01ad, B:101:0x01b4, B:106:0x01c7, B:108:0x01d5, B:113:0x01ec, B:117:0x01f7, B:111:0x01dc, B:118:0x01fa, B:132:0x0230, B:134:0x023c, B:135:0x023f, B:136:0x0243, B:137:0x0248, B:139:0x024c, B:145:0x025d, B:149:0x0266, B:151:0x026c, B:152:0x027e, B:153:0x027f, B:155:0x0283, B:157:0x0287, B:159:0x028b, B:160:0x028e, B:162:0x0294, B:164:0x02a3, B:166:0x02b0, B:168:0x02b4, B:170:0x02ba, B:172:0x02be, B:174:0x02c8, B:175:0x02d7, B:179:0x02e4, B:185:0x02f3, B:187:0x0301, B:189:0x0305, B:191:0x0309, B:196:0x031b, B:201:0x0326, B:203:0x032a, B:207:0x0339, B:205:0x0335, B:197:0x031e, B:199:0x0322), top: B:407:0x002e }] */
    /* JADX WARN: Removed duplicated region for block: B:116:0x01f3 A[LOOP:4: B:64:0x00ee->B:116:0x01f3, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:227:0x0396 A[Catch: CryptoException -> 0x000f, IllegalStateException -> 0x0084, TRY_LEAVE, TryCatch #1 {CryptoException -> 0x000f, blocks: (B:3:0x0003, B:5:0x0007, B:11:0x0013, B:13:0x0018, B:15:0x001e, B:22:0x0044, B:24:0x0066, B:26:0x007a, B:37:0x0097, B:32:0x008c, B:225:0x0390, B:227:0x0396, B:237:0x03bf, B:239:0x03c3, B:241:0x03c8, B:244:0x03cf, B:246:0x03d3, B:248:0x03db, B:251:0x03e9, B:254:0x03ee, B:256:0x03f2, B:260:0x0407, B:262:0x040a, B:265:0x040f, B:267:0x0413, B:269:0x041b, B:271:0x0429, B:272:0x042f, B:273:0x0430, B:274:0x0433, B:275:0x0434, B:277:0x0438, B:210:0x035d, B:212:0x0363, B:217:0x0373, B:219:0x0377, B:221:0x037b, B:222:0x0384, B:224:0x038c), top: B:408:0x0003 }] */
    /* JADX WARN: Removed duplicated region for block: B:232:0x03a8  */
    /* JADX WARN: Removed duplicated region for block: B:359:0x056c A[Catch: CryptoException -> 0x045a, IllegalStateException -> 0x0522, TryCatch #8 {IllegalStateException -> 0x0522, blocks: (B:279:0x0443, B:370:0x058e, B:357:0x0566, B:359:0x056c, B:296:0x0472, B:308:0x04a5, B:316:0x04b9, B:318:0x04bf, B:322:0x04ca, B:335:0x04f8, B:337:0x0506, B:341:0x0511, B:342:0x0513, B:344:0x051e, B:347:0x0525, B:349:0x052a, B:353:0x0545, B:350:0x0530, B:352:0x0536, B:354:0x0556, B:356:0x0558, B:369:0x058d, B:372:0x0596, B:376:0x059c, B:377:0x059d), top: B:420:0x023a }] */
    /* JADX WARN: Removed duplicated region for block: B:363:0x057e  */
    /* JADX WARN: Removed duplicated region for block: B:365:0x0581 A[LOOP:1: B:237:0x03bf->B:365:0x0581, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:386:0x05c2  */
    /* JADX WARN: Removed duplicated region for block: B:392:0x05dc  */
    /* JADX WARN: Removed duplicated region for block: B:395:0x05e7  */
    /* JADX WARN: Removed duplicated region for block: B:397:0x05ea  */
    /* JADX WARN: Removed duplicated region for block: B:400:0x05f9  */
    /* JADX WARN: Removed duplicated region for block: B:401:0x05fc  */
    /* JADX WARN: Removed duplicated region for block: B:443:0x058e A[EDGE_INSN: B:443:0x058e->B:370:0x058e BREAK  A[LOOP:1: B:237:0x03bf->B:365:0x0581], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:467:0x01f2 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:85:0x014d A[Catch: IllegalStateException -> 0x00ac, CryptoException -> 0x00b0, TRY_ENTER, TryCatch #0 {CryptoException -> 0x00b0, blocks: (B:129:0x0226, B:45:0x00a9, B:55:0x00bb, B:57:0x00bf, B:59:0x00c5, B:63:0x00df, B:64:0x00ee, B:68:0x00fb, B:70:0x0101, B:119:0x0205, B:121:0x020b, B:122:0x020e, B:124:0x0214, B:126:0x0218, B:72:0x010f, B:74:0x0116, B:75:0x0126, B:77:0x0136, B:81:0x0145, B:82:0x0147, B:85:0x014d, B:87:0x0151, B:89:0x015b, B:91:0x0165, B:92:0x018d, B:93:0x0195, B:94:0x0196, B:96:0x019d, B:98:0x01a5, B:100:0x01ad, B:101:0x01b4, B:106:0x01c7, B:108:0x01d5, B:113:0x01ec, B:117:0x01f7, B:111:0x01dc, B:118:0x01fa, B:132:0x0230, B:134:0x023c, B:135:0x023f, B:136:0x0243, B:137:0x0248, B:139:0x024c, B:145:0x025d, B:149:0x0266, B:151:0x026c, B:152:0x027e, B:153:0x027f, B:155:0x0283, B:157:0x0287, B:159:0x028b, B:160:0x028e, B:162:0x0294, B:164:0x02a3, B:166:0x02b0, B:168:0x02b4, B:170:0x02ba, B:172:0x02be, B:174:0x02c8, B:175:0x02d7, B:179:0x02e4, B:185:0x02f3, B:187:0x0301, B:189:0x0305, B:191:0x0309, B:196:0x031b, B:201:0x0326, B:203:0x032a, B:207:0x0339, B:205:0x0335, B:197:0x031e, B:199:0x0322), top: B:407:0x002e }] */
    /* JADX WARN: Type inference failed for: r11v0 */
    /* JADX WARN: Type inference failed for: r11v1, types: [boolean] */
    /* JADX WARN: Type inference failed for: r11v19 */
    /* JADX WARN: Type inference failed for: r11v2 */
    /* JADX WARN: Type inference failed for: r11v20 */
    /* JADX WARN: Type inference failed for: r11v21 */
    /* JADX WARN: Type inference failed for: r11v22 */
    /* JADX WARN: Type inference failed for: r11v26 */
    /* JADX WARN: Type inference failed for: r11v3 */
    /* JADX WARN: Type inference failed for: r11v37 */
    /* JADX WARN: Type inference failed for: r11v39 */
    /* JADX WARN: Type inference failed for: r11v4 */
    /* JADX WARN: Type inference failed for: r11v42 */
    /* JADX WARN: Type inference failed for: r11v46 */
    /* JADX WARN: Type inference failed for: r11v47 */
    /* JADX WARN: Type inference failed for: r11v5 */
    /* JADX WARN: Type inference failed for: r11v6 */
    /* JADX WARN: Type inference failed for: r11v8 */
    /* JADX WARN: Type inference failed for: r13v15 */
    /* JADX WARN: Type inference failed for: r13v16 */
    /* JADX WARN: Type inference failed for: r13v17, types: [java.lang.Object, java.lang.Throwable, java.nio.ByteBuffer] */
    /* JADX WARN: Type inference failed for: r13v18 */
    /* JADX WARN: Type inference failed for: r13v20 */
    /* JADX WARN: Type inference failed for: r13v21 */
    /* JADX WARN: Type inference failed for: r13v22 */
    /* JADX WARN: Type inference failed for: r2v15 */
    /* JADX WARN: Type inference failed for: r2v8 */
    /* JADX WARN: Type inference failed for: r2v9, types: [android.media.MediaFormat, java.lang.Object, java.lang.Throwable] */
    /* JADX WARN: Type inference failed for: r30v0, types: [com.google.android.gms.internal.ads.JE] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void n(long r31, long r33) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 1557
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.JE.n(long, long):void");
    }

    public abstract boolean o();

    public boolean p() {
        boolean zZze;
        if (this.C == null) {
            return false;
        }
        if (l()) {
            zZze = this.n;
        } else {
            AF af = this.i;
            af.getClass();
            zZze = af.zze();
        }
        if (zZze || this.f1 >= 0) {
            return true;
        }
        if (this.d1 == -9223372036854775807L) {
            return false;
        }
        this.g.getClass();
        return SystemClock.elapsedRealtime() < this.d1;
    }

    public final int q(C1832aG c1832aG) throws zzik {
        try {
            return I(this.t, c1832aG);
        } catch (zztq e) {
            throw b0(e, c1832aG, false, 4002);
        }
    }

    public abstract float r(float f, C1832aG[] c1832aGArr);

    public zztb s(IllegalStateException illegalStateException, HE he) {
        return new zztb(illegalStateException, he);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:236:0x043a  */
    /* JADX WARN: Removed duplicated region for block: B:242:0x0455  */
    /* JADX WARN: Removed duplicated region for block: B:259:0x048e A[Catch: Exception -> 0x01ba, TryCatch #8 {Exception -> 0x01ba, blocks: (B:101:0x01a0, B:103:0x01a4, B:105:0x01b2, B:122:0x0219, B:109:0x01c2, B:111:0x01ca, B:112:0x01d0, B:114:0x01d8, B:115:0x01de, B:117:0x01e6, B:118:0x01ec, B:120:0x01f4, B:121:0x01fa, B:123:0x021d, B:127:0x023b, B:129:0x0240, B:131:0x0244, B:132:0x0254, B:136:0x0274, B:138:0x027a, B:140:0x0280, B:141:0x029a, B:143:0x029e, B:145:0x02a3, B:150:0x02ad, B:152:0x02b3, B:153:0x02bf, B:155:0x02c5, B:156:0x02cd, B:158:0x02d2, B:159:0x02da, B:161:0x02df, B:162:0x02e7, B:164:0x02ec, B:165:0x02f4, B:167:0x02f8, B:168:0x0300, B:171:0x030a, B:172:0x0326, B:174:0x032a, B:176:0x033a, B:177:0x033f, B:179:0x0343, B:180:0x0348, B:181:0x0354, B:183:0x035b, B:185:0x036b, B:186:0x0370, B:188:0x0374, B:189:0x0379, B:191:0x037d, B:192:0x0382, B:194:0x0386, B:195:0x038b, B:197:0x038f, B:198:0x0394, B:200:0x0398, B:201:0x039d, B:203:0x03a1, B:204:0x03a6, B:206:0x03aa, B:207:0x03af, B:209:0x03b3, B:210:0x03b8, B:212:0x03bc, B:213:0x03c1, B:215:0x03c5, B:216:0x03ca, B:218:0x03ce, B:219:0x03d3, B:221:0x03d7, B:222:0x03dc, B:224:0x03e0, B:225:0x03e5, B:227:0x03e9, B:228:0x03ee, B:230:0x03f2, B:231:0x03f7, B:232:0x0403, B:234:0x0406, B:235:0x0412, B:237:0x043e, B:239:0x044a, B:243:0x0456, B:245:0x045a, B:247:0x0462, B:249:0x046a, B:251:0x0472, B:253:0x047a, B:255:0x0482, B:267:0x04a8, B:259:0x048e, B:261:0x0498, B:263:0x04a2), top: B:338:0x01a0 }] */
    /* JADX WARN: Removed duplicated region for block: B:301:0x0549 A[Catch: zztf -> 0x0564, TryCatch #7 {zztf -> 0x0564, blocks: (B:299:0x0524, B:301:0x0549, B:303:0x0554, B:305:0x0561, B:309:0x057b, B:312:0x0583, B:313:0x0585, B:308:0x0566, B:315:0x0589, B:316:0x058a, B:318:0x0591, B:319:0x0592, B:320:0x059c, B:322:0x059f), top: B:337:0x0058 }] */
    /* JADX WARN: Removed duplicated region for block: B:302:0x0552  */
    /* JADX WARN: Removed duplicated region for block: B:305:0x0561 A[Catch: zztf -> 0x0564, TryCatch #7 {zztf -> 0x0564, blocks: (B:299:0x0524, B:301:0x0549, B:303:0x0554, B:305:0x0561, B:309:0x057b, B:312:0x0583, B:313:0x0585, B:308:0x0566, B:315:0x0589, B:316:0x058a, B:318:0x0591, B:319:0x0592, B:320:0x059c, B:322:0x059f), top: B:337:0x0058 }] */
    /* JADX WARN: Removed duplicated region for block: B:308:0x0566 A[Catch: zztf -> 0x0564, TryCatch #7 {zztf -> 0x0564, blocks: (B:299:0x0524, B:301:0x0549, B:303:0x0554, B:305:0x0561, B:309:0x057b, B:312:0x0583, B:313:0x0585, B:308:0x0566, B:315:0x0589, B:316:0x058a, B:318:0x0591, B:319:0x0592, B:320:0x059c, B:322:0x059f), top: B:337:0x0058 }] */
    /* JADX WARN: Removed duplicated region for block: B:311:0x0581  */
    /* JADX WARN: Removed duplicated region for block: B:329:0x04ae A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:334:0x0154 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:356:0x04ec A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:357:0x0583 A[SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r10v0 */
    /* JADX WARN: Type inference failed for: r10v16 */
    /* JADX WARN: Type inference failed for: r10v17 */
    /* JADX WARN: Type inference failed for: r10v19 */
    /* JADX WARN: Type inference failed for: r10v2 */
    /* JADX WARN: Type inference failed for: r10v21 */
    /* JADX WARN: Type inference failed for: r10v3, types: [com.google.android.gms.internal.ads.JE] */
    /* JADX WARN: Type inference failed for: r10v56 */
    /* JADX WARN: Type inference failed for: r10v57 */
    /* JADX WARN: Type inference failed for: r1v7, types: [java.util.ArrayDeque] */
    /* JADX WARN: Type inference failed for: r5v8, types: [com.google.android.gms.internal.ads.GE] */
    /* JADX WARN: Type inference failed for: r6v0 */
    /* JADX WARN: Type inference failed for: r6v1, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r6v3 */
    /* JADX WARN: Type inference failed for: r8v11 */
    /* JADX WARN: Type inference failed for: r8v15, types: [com.google.android.gms.internal.ads.Lr] */
    /* JADX WARN: Type inference failed for: r8v68 */
    /* JADX WARN: Type inference failed for: r8v69 */
    /* JADX WARN: Type inference failed for: r8v70 */
    /* JADX WARN: Type inference failed for: r8v9 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void t() throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 1449
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.JE.t():void");
    }

    public void u(long j) {
        this.A1 = j;
        while (true) {
            ArrayDeque arrayDeque = this.A;
            if (arrayDeque.isEmpty() || j < ((IE) arrayDeque.peek()).a) {
                return;
            }
            IE ie = (IE) arrayDeque.poll();
            ie.getClass();
            D(ie);
            W();
        }
    }

    public void v() {
    }

    public final void w() {
        try {
            GE ge = this.I;
            if (ge != null) {
                ge.l();
                this.y1.b++;
                HE he = this.X;
                if (he == null) {
                    throw null;
                }
                U(he.a);
            }
            this.I = null;
            this.D1 = null;
            y();
        } catch (Throwable th) {
            this.I = null;
            this.D1 = null;
            y();
            throw th;
        }
    }

    public void x() {
        this.e1 = -1;
        this.w.e = null;
        this.f1 = -1;
        this.g1 = null;
        this.d1 = -9223372036854775807L;
        this.r1 = false;
        this.c1 = -9223372036854775807L;
        this.q1 = false;
        this.h1 = false;
        this.i1 = false;
        this.t1 = -9223372036854775807L;
        this.u1 = -9223372036854775807L;
        this.A1 = -9223372036854775807L;
        this.o1 = 0;
        this.p1 = 0;
        this.n1 = this.m1 ? 1 : 0;
    }

    public final void y() {
        x();
        this.V = null;
        this.X = null;
        this.J = null;
        this.K = null;
        this.L = false;
        this.s1 = false;
        this.M = -1.0f;
        this.Y = false;
        this.Z = false;
        this.m1 = false;
        this.n1 = 0;
    }

    public boolean z() {
        if (this.I == null) {
            return false;
        }
        int i = this.p1;
        if (i == 3 || (this.Y && !this.s1)) {
            w();
            return true;
        }
        if (i == 2) {
            try {
                C2883yp c2883yp = this.E1;
                c2883yp.getClass();
                this.D1 = c2883yp;
                this.o1 = 0;
                this.p1 = 0;
            } catch (zzik e) {
                AbstractC2096gb.M("MediaCodecRenderer", "Failed to update the DRM session, releasing the codec instead.", e);
                w();
                return true;
            }
        }
        P();
        return false;
    }
}
