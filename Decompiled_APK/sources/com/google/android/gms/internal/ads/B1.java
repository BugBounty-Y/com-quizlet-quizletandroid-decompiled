package com.google.android.gms.internal.ads;

import android.util.SparseArray;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.PriorityQueue;

/* loaded from: classes2.dex */
public final class B1 implements U {
    public static final byte[] J = {-94, 57, 79, 82, 90, -101, 79, 20, -94, 68, 108, 66, 124, 100, -115, -12};
    public static final C1832aG K;
    public int A;
    public int B;
    public int C;
    public boolean D;
    public boolean E;
    public W F;
    public InterfaceC2380n0[] G;
    public InterfaceC2380n0[] H;
    public boolean I;
    public final Z1 a;
    public final int b;
    public final List c;
    public final byte[] h;
    public final Kn i;
    public final androidx.navigation.internal.m n;
    public Bu o;
    public int p;
    public int q;
    public long r;
    public int s;
    public Kn t;
    public long u;
    public int v;
    public long w;
    public long x;
    public long y;
    public A1 z;
    public final C1732Mb j = new C1732Mb(3);
    public final Kn k = new Kn(16);
    public final Kn e = new Kn(LA.w);
    public final Kn f = new Kn(6);
    public final Kn g = new Kn();
    public final ArrayDeque l = new ArrayDeque();
    public final ArrayDeque m = new ArrayDeque();
    public final SparseArray d = new SparseArray();

    static {
        EF ef = new EF();
        ef.d("application/x-emsg");
        K = new C1832aG(ef);
    }

    public B1(Z1 z1, int i, AbstractC2330lu abstractC2330lu) {
        this.a = z1;
        this.b = i;
        this.c = Collections.unmodifiableList(abstractC2330lu);
        byte[] bArr = new byte[16];
        this.h = bArr;
        this.i = new Kn(bArr);
        C2244ju c2244ju = AbstractC2330lu.b;
        this.o = Bu.e;
        this.x = -9223372036854775807L;
        this.w = -9223372036854775807L;
        this.y = -9223372036854775807L;
        this.F = W.O0;
        this.G = new InterfaceC2380n0[0];
        this.H = new InterfaceC2380n0[0];
        this.n = new androidx.navigation.internal.m(new Os(this, 3));
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x00e2  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x00e5  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x00eb  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x00f3  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.gms.internal.ads.zzs a(java.util.ArrayList r18) {
        /*
            Method dump skipped, instructions count: 283
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.B1.a(java.util.ArrayList):com.google.android.gms.internal.ads.zzs");
    }

    public static void b(Kn kn, int i, K1 k1) throws zzaz {
        kn.j(i + 8);
        int iU = kn.u();
        byte[] bArr = AbstractC2767w1.a;
        if ((iU & 1) != 0) {
            throw zzaz.b("Overriding TrackEncryptionBox parameters is unsupported.");
        }
        boolean z = (iU & 2) != 0;
        int iC = kn.C();
        if (iC == 0) {
            Arrays.fill(k1.l, 0, k1.e, false);
            return;
        }
        int i2 = k1.e;
        if (iC != i2) {
            throw zzaz.a(null, "Senc sample count " + iC + " is different from fragment sample count" + i2);
        }
        Arrays.fill(k1.l, 0, iC, z);
        int iS = kn.s();
        Kn kn2 = k1.n;
        kn2.g(iS);
        k1.k = true;
        k1.o = true;
        kn.f(0, kn2.a, kn2.c);
        kn2.j(0);
        k1.o = false;
    }

    /* JADX WARN: Code restructure failed: missing block: B:100:0x02b2, code lost:
    
        r10 = (r10 * 125) / 100;
        r5.h = new int[r10];
        r5.i = new long[r10];
        r5.j = new boolean[r10];
        r5.l = new boolean[r10];
     */
    /* JADX WARN: Code restructure failed: missing block: B:101:0x02c6, code lost:
    
        r2 = 0;
        r4 = 0;
        r9 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:102:0x02c9, code lost:
    
        r26 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:103:0x02cb, code lost:
    
        if (r2 >= r7) goto L340;
     */
    /* JADX WARN: Code restructure failed: missing block: B:104:0x02cd, code lost:
    
        r10 = (com.google.android.gms.internal.ads.Mp) r6.get(r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:105:0x02d5, code lost:
    
        if (r10.b != r14) goto L169;
     */
    /* JADX WARN: Code restructure failed: missing block: B:106:0x02d7, code lost:
    
        r28 = r4 + 1;
        r10 = r10.c;
        r10.j(8);
        r13 = r10.u();
        r14 = r12.d;
        r29 = r2;
        r2 = r5.a;
        r30 = com.google.android.gms.internal.ads.Yo.a;
        r30 = r3;
        r5.g[r4] = r10.C();
        r3 = r5.f;
        r31 = r4;
        r3 = r5.b;
        r3[r31] = r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:107:0x0306, code lost:
    
        if ((r13 & 1) == 0) goto L109;
     */
    /* JADX WARN: Code restructure failed: missing block: B:108:0x0308, code lost:
    
        r3[r31] = r3 + r10.u();
     */
    /* JADX WARN: Code restructure failed: missing block: B:110:0x0315, code lost:
    
        if ((r13 & 4) == 0) goto L112;
     */
    /* JADX WARN: Code restructure failed: missing block: B:111:0x0317, code lost:
    
        r3 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:112:0x0319, code lost:
    
        r3 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:113:0x031a, code lost:
    
        r4 = r2.d;
     */
    /* JADX WARN: Code restructure failed: missing block: B:114:0x031c, code lost:
    
        if (r3 == false) goto L116;
     */
    /* JADX WARN: Code restructure failed: missing block: B:115:0x031e, code lost:
    
        r32 = r10.u();
     */
    /* JADX WARN: Code restructure failed: missing block: B:116:0x0323, code lost:
    
        r32 = r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:117:0x0325, code lost:
    
        r33 = r3;
        r3 = r13 & 256;
        r3 = r13 & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH;
        r3 = r13 & 1024;
        r13 = r13 & 2048;
        r14 = r14.a;
        r3 = r14.i;
     */
    /* JADX WARN: Code restructure failed: missing block: B:118:0x0339, code lost:
    
        if (r3 == null) goto L131;
     */
    /* JADX WARN: Code restructure failed: missing block: B:119:0x033b, code lost:
    
        r37 = r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:120:0x0341, code lost:
    
        if (r3.length != 1) goto L123;
     */
    /* JADX WARN: Code restructure failed: missing block: B:121:0x0343, code lost:
    
        r3 = r14.j;
     */
    /* JADX WARN: Code restructure failed: missing block: B:122:0x0345, code lost:
    
        if (r3 != null) goto L124;
     */
    /* JADX WARN: Code restructure failed: missing block: B:124:0x0349, code lost:
    
        r39 = r3[0];
     */
    /* JADX WARN: Code restructure failed: missing block: B:125:0x034f, code lost:
    
        if (r39 != 0) goto L127;
     */
    /* JADX WARN: Code restructure failed: missing block: B:126:0x0351, code lost:
    
        r38 = r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:127:0x0354, code lost:
    
        r45 = java.math.RoundingMode.DOWN;
        r38 = r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:128:0x037c, code lost:
    
        if ((com.google.android.gms.internal.ads.Yo.v(r39, 1000000, r14.d, r45) + com.google.android.gms.internal.ads.Yo.v(r38[0], 1000000, r14.c, r45)) >= r14.e) goto L130;
     */
    /* JADX WARN: Code restructure failed: missing block: B:130:0x037f, code lost:
    
        r26 = r38[0];
     */
    /* JADX WARN: Code restructure failed: missing block: B:131:0x0382, code lost:
    
        r37 = r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:132:0x0385, code lost:
    
        r4 = r5.h;
        r13 = r5.i;
        r3 = r5.j;
        r3 = r5.g[r31] + r9;
        r40 = r9;
        r9 = r5.p;
        r4 = r40;
     */
    /* JADX WARN: Code restructure failed: missing block: B:133:0x039e, code lost:
    
        if (r4 >= r3) goto L341;
     */
    /* JADX WARN: Code restructure failed: missing block: B:134:0x03a0, code lost:
    
        if (r3 == 0) goto L137;
     */
    /* JADX WARN: Code restructure failed: missing block: B:135:0x03a2, code lost:
    
        r31 = r3;
        r3 = r10.u();
     */
    /* JADX WARN: Code restructure failed: missing block: B:136:0x03ac, code lost:
    
        r40 = r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:137:0x03af, code lost:
    
        r31 = r3;
        r3 = r2.b;
     */
    /* JADX WARN: Code restructure failed: missing block: B:139:0x03b6, code lost:
    
        if (r3 < 0) goto L310;
     */
    /* JADX WARN: Code restructure failed: missing block: B:140:0x03b8, code lost:
    
        if (r3 == 0) goto L142;
     */
    /* JADX WARN: Code restructure failed: missing block: B:141:0x03ba, code lost:
    
        r43 = r7;
        r7 = r10.u();
     */
    /* JADX WARN: Code restructure failed: missing block: B:142:0x03c5, code lost:
    
        r43 = r7;
        r7 = r2.c;
     */
    /* JADX WARN: Code restructure failed: missing block: B:143:0x03c9, code lost:
    
        if (r7 < 0) goto L311;
     */
    /* JADX WARN: Code restructure failed: missing block: B:144:0x03cb, code lost:
    
        if (r3 == 0) goto L146;
     */
    /* JADX WARN: Code restructure failed: missing block: B:145:0x03cd, code lost:
    
        r4 = r10.u();
     */
    /* JADX WARN: Code restructure failed: missing block: B:146:0x03d2, code lost:
    
        if (r40 != 0) goto L150;
     */
    /* JADX WARN: Code restructure failed: missing block: B:147:0x03d4, code lost:
    
        if (r33 == false) goto L149;
     */
    /* JADX WARN: Code restructure failed: missing block: B:148:0x03d6, code lost:
    
        r4 = r32;
        r40 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:149:0x03db, code lost:
    
        r40 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:150:0x03dd, code lost:
    
        r4 = r37;
     */
    /* JADX WARN: Code restructure failed: missing block: B:151:0x03df, code lost:
    
        if (r13 == 0) goto L154;
     */
    /* JADX WARN: Code restructure failed: missing block: B:152:0x03e1, code lost:
    
        r44 = r2;
        r2 = r10.u();
     */
    /* JADX WARN: Code restructure failed: missing block: B:153:0x03eb, code lost:
    
        r45 = r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:154:0x03ee, code lost:
    
        r44 = r2;
        r2 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:155:0x03f2, code lost:
    
        r1 = com.google.android.gms.internal.ads.Yo.v((r2 + r9) - r26, 1000000, r14.c, java.math.RoundingMode.DOWN);
        r13[r40] = r1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:156:0x0409, code lost:
    
        if (r5.q != false) goto L158;
     */
    /* JADX WARN: Code restructure failed: missing block: B:157:0x040b, code lost:
    
        r13[r40] = r1 + r12.d.h;
     */
    /* JADX WARN: Code restructure failed: missing block: B:158:0x0413, code lost:
    
        r4[r40] = r7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:159:0x041b, code lost:
    
        if (((r4 >> 16) & 1) != 0) goto L161;
     */
    /* JADX WARN: Code restructure failed: missing block: B:160:0x041d, code lost:
    
        r1 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:161:0x0420, code lost:
    
        r1 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:162:0x0421, code lost:
    
        r3[r40] = r1;
        r9 = r9 + r3;
        r4 = r40 + 1;
        r3 = r31;
        r7 = r43;
        r2 = r44;
        r1 = r45;
     */
    /* JADX WARN: Code restructure failed: missing block: B:164:0x0442, code lost:
    
        throw com.google.android.gms.internal.ads.zzaz.a(null, "Unexpected negative value: " + r7);
     */
    /* JADX WARN: Code restructure failed: missing block: B:166:0x0454, code lost:
    
        throw com.google.android.gms.internal.ads.zzaz.a(null, "Unexpected negative value: " + r3);
     */
    /* JADX WARN: Code restructure failed: missing block: B:167:0x0455, code lost:
    
        r45 = r1;
        r43 = r7;
        r5.p = r9;
        r4 = r28;
        r9 = r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:169:0x0464, code lost:
    
        r45 = r1;
        r29 = r2;
        r30 = r3;
        r43 = r7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:170:0x0471, code lost:
    
        r2 = r29 + 1;
        r3 = r30;
        r7 = r43;
        r1 = r45;
        r14 = 1953658222;
     */
    /* JADX WARN: Code restructure failed: missing block: B:171:0x047e, code lost:
    
        r45 = r1;
        r30 = r3;
        r1 = r12.d;
        r2 = r5.a;
        r2.getClass();
        r1 = r1.a.l[r2.a];
        r2 = r8.w(1935763834);
     */
    /* JADX WARN: Code restructure failed: missing block: B:172:0x0498, code lost:
    
        if (r2 == null) goto L197;
     */
    /* JADX WARN: Code restructure failed: missing block: B:173:0x049a, code lost:
    
        r1.getClass();
        r2 = r2.c;
        r2.j(8);
     */
    /* JADX WARN: Code restructure failed: missing block: B:174:0x04aa, code lost:
    
        if ((r2.u() & 1) != 1) goto L176;
     */
    /* JADX WARN: Code restructure failed: missing block: B:175:0x04ac, code lost:
    
        r2.k(8);
     */
    /* JADX WARN: Code restructure failed: missing block: B:176:0x04af, code lost:
    
        r3 = r2.z();
        r4 = r2.C();
        r7 = r5.e;
     */
    /* JADX WARN: Code restructure failed: missing block: B:177:0x04b9, code lost:
    
        if (r4 > r7) goto L312;
     */
    /* JADX WARN: Code restructure failed: missing block: B:178:0x04bb, code lost:
    
        r7 = r1.d;
     */
    /* JADX WARN: Code restructure failed: missing block: B:179:0x04bd, code lost:
    
        if (r3 != 0) goto L188;
     */
    /* JADX WARN: Code restructure failed: missing block: B:180:0x04bf, code lost:
    
        r3 = r5.l;
        r9 = 0;
        r13 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:181:0x04c3, code lost:
    
        if (r13 >= r4) goto L344;
     */
    /* JADX WARN: Code restructure failed: missing block: B:182:0x04c5, code lost:
    
        r10 = r2.z();
        r9 = r9 + r10;
     */
    /* JADX WARN: Code restructure failed: missing block: B:183:0x04ca, code lost:
    
        if (r10 <= r7) goto L185;
     */
    /* JADX WARN: Code restructure failed: missing block: B:184:0x04cc, code lost:
    
        r10 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:185:0x04ce, code lost:
    
        r10 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:186:0x04cf, code lost:
    
        r3[r13] = r10;
        r13 = r13 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:187:0x04d6, code lost:
    
        r13 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:188:0x04d8, code lost:
    
        if (r3 <= r7) goto L190;
     */
    /* JADX WARN: Code restructure failed: missing block: B:189:0x04da, code lost:
    
        r2 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:190:0x04dc, code lost:
    
        r2 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:191:0x04dd, code lost:
    
        r9 = r3 * r4;
        r13 = false;
        java.util.Arrays.fill(r5.l, 0, r4, r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:192:0x04e5, code lost:
    
        java.util.Arrays.fill(r5.l, r4, r5.e, r13);
     */
    /* JADX WARN: Code restructure failed: missing block: B:193:0x04ec, code lost:
    
        if (r9 <= 0) goto L197;
     */
    /* JADX WARN: Code restructure failed: missing block: B:194:0x04ee, code lost:
    
        r5.n.g(r9);
        r5.k = true;
        r5.o = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:196:0x0514, code lost:
    
        throw com.google.android.gms.internal.ads.zzaz.a(null, "Saiz sample count " + r4 + " is greater than fragment sample count" + r7);
     */
    /* JADX WARN: Code restructure failed: missing block: B:197:0x0515, code lost:
    
        r2 = r8.w(1935763823);
     */
    /* JADX WARN: Code restructure failed: missing block: B:198:0x051c, code lost:
    
        if (r2 == null) goto L209;
     */
    /* JADX WARN: Code restructure failed: missing block: B:199:0x051e, code lost:
    
        r2 = r2.c;
        r2.j(8);
        r4 = r2.u();
     */
    /* JADX WARN: Code restructure failed: missing block: B:200:0x052c, code lost:
    
        if ((r4 & 1) != 1) goto L202;
     */
    /* JADX WARN: Code restructure failed: missing block: B:201:0x052e, code lost:
    
        r2.k(8);
     */
    /* JADX WARN: Code restructure failed: missing block: B:202:0x0531, code lost:
    
        r3 = r2.C();
     */
    /* JADX WARN: Code restructure failed: missing block: B:203:0x0535, code lost:
    
        if (r3 != 1) goto L313;
     */
    /* JADX WARN: Code restructure failed: missing block: B:204:0x0537, code lost:
    
        r3 = com.google.android.gms.internal.ads.AbstractC2767w1.a(r4);
        r9 = r5.c;
     */
    /* JADX WARN: Code restructure failed: missing block: B:205:0x053d, code lost:
    
        if (r3 != 0) goto L207;
     */
    /* JADX WARN: Code restructure failed: missing block: B:206:0x053f, code lost:
    
        r2 = r2.H();
     */
    /* JADX WARN: Code restructure failed: missing block: B:207:0x0544, code lost:
    
        r2 = r2.I();
     */
    /* JADX WARN: Code restructure failed: missing block: B:208:0x0548, code lost:
    
        r5.c = r9 + r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:209:0x054b, code lost:
    
        r2 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:211:0x0560, code lost:
    
        throw com.google.android.gms.internal.ads.zzaz.a(null, "Unexpected saio entry count: " + r3);
     */
    /* JADX WARN: Code restructure failed: missing block: B:212:0x0561, code lost:
    
        r3 = r8.w(1936027235);
     */
    /* JADX WARN: Code restructure failed: missing block: B:213:0x0568, code lost:
    
        if (r3 == null) goto L215;
     */
    /* JADX WARN: Code restructure failed: missing block: B:214:0x056a, code lost:
    
        b(r3.c, 0, r5);
     */
    /* JADX WARN: Code restructure failed: missing block: B:215:0x0570, code lost:
    
        if (r1 == null) goto L217;
     */
    /* JADX WARN: Code restructure failed: missing block: B:216:0x0572, code lost:
    
        r33 = r1.b;
     */
    /* JADX WARN: Code restructure failed: missing block: B:217:0x0577, code lost:
    
        r33 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:218:0x0579, code lost:
    
        r1 = null;
        r3 = null;
        r4 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:220:0x0580, code lost:
    
        if (r4 >= r6.size()) goto L347;
     */
    /* JADX WARN: Code restructure failed: missing block: B:221:0x0582, code lost:
    
        r7 = (com.google.android.gms.internal.ads.Mp) r6.get(r4);
        r8 = r7.c;
        r7 = r7.b;
     */
    /* JADX WARN: Code restructure failed: missing block: B:222:0x0592, code lost:
    
        if (r7 != 1935828848) goto L227;
     */
    /* JADX WARN: Code restructure failed: missing block: B:223:0x0594, code lost:
    
        r8.j(12);
     */
    /* JADX WARN: Code restructure failed: missing block: B:224:0x059d, code lost:
    
        if (r8.u() != 1936025959) goto L226;
     */
    /* JADX WARN: Code restructure failed: missing block: B:225:0x059f, code lost:
    
        r1 = r8;
     */
    /* JADX WARN: Code restructure failed: missing block: B:228:0x05a7, code lost:
    
        if (r7 != 1936158820) goto L226;
     */
    /* JADX WARN: Code restructure failed: missing block: B:229:0x05a9, code lost:
    
        r8.j(12);
     */
    /* JADX WARN: Code restructure failed: missing block: B:230:0x05b0, code lost:
    
        if (r8.u() != 1936025959) goto L226;
     */
    /* JADX WARN: Code restructure failed: missing block: B:231:0x05b2, code lost:
    
        r3 = r8;
     */
    /* JADX WARN: Code restructure failed: missing block: B:232:0x05b4, code lost:
    
        r4 = r4 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:234:0x05b9, code lost:
    
        if (r1 == null) goto L236;
     */
    /* JADX WARN: Code restructure failed: missing block: B:235:0x05bb, code lost:
    
        if (r3 != null) goto L237;
     */
    /* JADX WARN: Code restructure failed: missing block: B:236:0x05bd, code lost:
    
        r4 = r20;
        r8 = r21;
     */
    /* JADX WARN: Code restructure failed: missing block: B:237:0x05c3, code lost:
    
        r1.j(8);
        r7 = com.google.android.gms.internal.ads.AbstractC2767w1.a(r1.u());
        r8 = r21;
        r1.k(r8);
     */
    /* JADX WARN: Code restructure failed: missing block: B:238:0x05d5, code lost:
    
        if (r7 != 1) goto L240;
     */
    /* JADX WARN: Code restructure failed: missing block: B:239:0x05d7, code lost:
    
        r1.k(r8);
     */
    /* JADX WARN: Code restructure failed: missing block: B:241:0x05de, code lost:
    
        if (r1.u() != 1) goto L314;
     */
    /* JADX WARN: Code restructure failed: missing block: B:242:0x05e0, code lost:
    
        r3.j(8);
        r1 = com.google.android.gms.internal.ads.AbstractC2767w1.a(r3.u());
        r3.k(r8);
     */
    /* JADX WARN: Code restructure failed: missing block: B:243:0x05ee, code lost:
    
        if (r1 != 1) goto L249;
     */
    /* JADX WARN: Code restructure failed: missing block: B:245:0x05f6, code lost:
    
        if (r3.H() == 0) goto L315;
     */
    /* JADX WARN: Code restructure failed: missing block: B:246:0x05f8, code lost:
    
        r4 = r20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:248:0x0601, code lost:
    
        throw com.google.android.gms.internal.ads.zzaz.b("Variable length description in sgpd found (unsupported)");
     */
    /* JADX WARN: Code restructure failed: missing block: B:249:0x0602, code lost:
    
        r4 = r20;
     */
    /* JADX WARN: Code restructure failed: missing block: B:250:0x0604, code lost:
    
        if (r1 < r4) goto L252;
     */
    /* JADX WARN: Code restructure failed: missing block: B:251:0x0606, code lost:
    
        r3.k(r8);
     */
    /* JADX WARN: Code restructure failed: missing block: B:253:0x0611, code lost:
    
        if (r3.H() != 1) goto L316;
     */
    /* JADX WARN: Code restructure failed: missing block: B:254:0x0613, code lost:
    
        r3.k(1);
        r1 = r3.z();
        r36 = (r1 & 240) >> 4;
        r37 = r1 & 15;
     */
    /* JADX WARN: Code restructure failed: missing block: B:255:0x0625, code lost:
    
        if (r3.z() != 1) goto L264;
     */
    /* JADX WARN: Code restructure failed: missing block: B:256:0x0627, code lost:
    
        r34 = r3.z();
        r1 = r19;
        r7 = new byte[r1];
        r3.f(0, r7, r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:257:0x0633, code lost:
    
        if (r34 != 0) goto L259;
     */
    /* JADX WARN: Code restructure failed: missing block: B:258:0x0635, code lost:
    
        r1 = r3.z();
        r2 = new byte[r1];
        r3.f(0, r2, r1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:259:0x063e, code lost:
    
        r5.k = true;
        r5.m = new com.google.android.gms.internal.ads.J1(true, r33, r34, r7, r36, r37, r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:261:0x0656, code lost:
    
        throw com.google.android.gms.internal.ads.zzaz.b("Entry count in sgpd != 1 (unsupported).");
     */
    /* JADX WARN: Code restructure failed: missing block: B:263:0x065d, code lost:
    
        throw com.google.android.gms.internal.ads.zzaz.b("Entry count in sbgp != 1 (unsupported).");
     */
    /* JADX WARN: Code restructure failed: missing block: B:264:0x065e, code lost:
    
        r1 = r6.size();
        r2 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:265:0x0663, code lost:
    
        if (r2 >= r1) goto L348;
     */
    /* JADX WARN: Code restructure failed: missing block: B:266:0x0665, code lost:
    
        r3 = (com.google.android.gms.internal.ads.Mp) r6.get(r2);
     */
    /* JADX WARN: Code restructure failed: missing block: B:267:0x0670, code lost:
    
        if (r3.b != 1970628964) goto L272;
     */
    /* JADX WARN: Code restructure failed: missing block: B:268:0x0672, code lost:
    
        r3 = r3.c;
        r3.j(8);
        r7 = r54.h;
        r3.f(0, r7, 16);
     */
    /* JADX WARN: Code restructure failed: missing block: B:269:0x0687, code lost:
    
        if (java.util.Arrays.equals(r7, com.google.android.gms.internal.ads.B1.J) == false) goto L271;
     */
    /* JADX WARN: Code restructure failed: missing block: B:270:0x0689, code lost:
    
        b(r3, 16, r5);
     */
    /* JADX WARN: Code restructure failed: missing block: B:273:0x0694, code lost:
    
        r2 = r2 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:274:0x0697, code lost:
    
        r10 = 8;
        r12 = 16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:275:0x069d, code lost:
    
        r45 = r1;
        r25 = r2;
        r30 = r3;
        r10 = r4;
        r15 = r6;
     */
    /* JADX WARN: Code restructure failed: missing block: B:276:0x06a7, code lost:
    
        r6 = r15 + 1;
        r20 = r4;
        r21 = r8;
        r4 = r10;
        r19 = r12;
        r2 = r25;
        r3 = r30;
        r1 = r45;
     */
    /* JADX WARN: Code restructure failed: missing block: B:277:0x06b9, code lost:
    
        r45 = r1;
        r10 = r4;
        r1 = a(r11);
     */
    /* JADX WARN: Code restructure failed: missing block: B:278:0x06c7, code lost:
    
        if (r1 == null) goto L286;
     */
    /* JADX WARN: Code restructure failed: missing block: B:279:0x06c9, code lost:
    
        r3 = r45.size();
        r5 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:280:0x06ce, code lost:
    
        if (r5 >= r3) goto L349;
     */
    /* JADX WARN: Code restructure failed: missing block: B:281:0x06d0, code lost:
    
        r6 = r45;
        r7 = (com.google.android.gms.internal.ads.A1) r6.valueAt(r5);
        r9 = r7.d;
        r11 = r7.b.a;
        r14 = com.google.android.gms.internal.ads.Yo.a;
        r9 = r9.a.l[r11.a];
     */
    /* JADX WARN: Code restructure failed: missing block: B:282:0x06e8, code lost:
    
        if (r9 == null) goto L284;
     */
    /* JADX WARN: Code restructure failed: missing block: B:283:0x06ea, code lost:
    
        r9 = r9.b;
     */
    /* JADX WARN: Code restructure failed: missing block: B:284:0x06ed, code lost:
    
        r9 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:285:0x06ee, code lost:
    
        r9 = r1.a(r9);
        r14 = new com.google.android.gms.internal.ads.EF(r7.d.a.g);
        r14.a(r7.j);
        r14.p = r9;
        r7.a.a(new com.google.android.gms.internal.ads.C1832aG(r14));
        r5 = r5 + 1;
        r45 = r6;
     */
    /* JADX WARN: Code restructure failed: missing block: B:286:0x0715, code lost:
    
        r6 = r45;
     */
    /* JADX WARN: Code restructure failed: missing block: B:287:0x0720, code lost:
    
        if (r54.w == (-9223372036854775807L)) goto L302;
     */
    /* JADX WARN: Code restructure failed: missing block: B:288:0x0722, code lost:
    
        r1 = r6.size();
        r2 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:289:0x0727, code lost:
    
        if (r2 >= r1) goto L352;
     */
    /* JADX WARN: Code restructure failed: missing block: B:290:0x0729, code lost:
    
        r3 = (com.google.android.gms.internal.ads.A1) r6.valueAt(r2);
        r4 = r54.w;
        r7 = r3.f;
     */
    /* JADX WARN: Code restructure failed: missing block: B:291:0x0733, code lost:
    
        r9 = r3.b;
     */
    /* JADX WARN: Code restructure failed: missing block: B:292:0x0737, code lost:
    
        if (r7 >= r9.e) goto L353;
     */
    /* JADX WARN: Code restructure failed: missing block: B:294:0x073f, code lost:
    
        if (r9.i[r7] > r4) goto L354;
     */
    /* JADX WARN: Code restructure failed: missing block: B:296:0x0745, code lost:
    
        if (r9.j[r7] == false) goto L356;
     */
    /* JADX WARN: Code restructure failed: missing block: B:297:0x0747, code lost:
    
        r3.i = r7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:298:0x0749, code lost:
    
        r7 = r7 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:299:0x074e, code lost:
    
        r2 = r2 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:300:0x0754, code lost:
    
        r54.w = -9223372036854775807L;
     */
    /* JADX WARN: Code restructure failed: missing block: B:303:0x075e, code lost:
    
        r10 = r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:304:0x0769, code lost:
    
        if (r7.isEmpty() != false) goto L319;
     */
    /* JADX WARN: Code restructure failed: missing block: B:305:0x076b, code lost:
    
        ((com.google.android.gms.internal.ads.C2840xp) r7.peek()).e.add(r9);
     */
    /* JADX WARN: Code restructure failed: missing block: B:306:0x0777, code lost:
    
        r54.p = 0;
        r54.s = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:307:0x077c, code lost:
    
        return;
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x017e, code lost:
    
        r1 = r10;
        r19 = 16;
        r20 = 2;
        r21 = 4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x0188, code lost:
    
        if (r8 != 1836019558) goto L303;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x018a, code lost:
    
        r2 = r9.e;
        r3 = r2.size();
        r6 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x0191, code lost:
    
        if (r6 >= r3) goto L336;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x0193, code lost:
    
        r8 = (com.google.android.gms.internal.ads.C2840xp) r2.get(r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x019e, code lost:
    
        if (r8.b != 1953653094) goto L275;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x01a0, code lost:
    
        r9 = r8.w(1952868452);
        r9.getClass();
        r9 = r9.c;
        r9.j(r4);
        r10 = r9.u();
        r12 = com.google.android.gms.internal.ads.AbstractC2767w1.a;
        r12 = (com.google.android.gms.internal.ads.A1) r1.get(r9.u());
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x01bf, code lost:
    
        if (r12 != null) goto L53;
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x01c1, code lost:
    
        r15 = r6;
        r12 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x01c4, code lost:
    
        r13 = r10 & 1;
        r14 = r12.b;
        r15 = r6;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x01cb, code lost:
    
        if (r13 == 0) goto L56;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x01cd, code lost:
    
        r5 = r9.I();
        r14.b = r5;
        r14.c = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x01d5, code lost:
    
        r5 = r12.e;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x01d9, code lost:
    
        if ((r10 & 2) == 0) goto L59;
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x01db, code lost:
    
        r6 = r9.u() - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:0x01e2, code lost:
    
        r6 = r5.a;
     */
    /* JADX WARN: Code restructure failed: missing block: B:61:0x01e6, code lost:
    
        if ((r10 & 8) == 0) goto L63;
     */
    /* JADX WARN: Code restructure failed: missing block: B:62:0x01e8, code lost:
    
        r13 = r9.u();
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x01ef, code lost:
    
        r13 = r5.b;
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x01f3, code lost:
    
        if ((r10 & 16) == 0) goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:66:0x01f5, code lost:
    
        r7 = r9.u();
     */
    /* JADX WARN: Code restructure failed: missing block: B:67:0x01fc, code lost:
    
        r7 = r5.c;
     */
    /* JADX WARN: Code restructure failed: missing block: B:69:0x0200, code lost:
    
        if ((r10 & 32) == 0) goto L71;
     */
    /* JADX WARN: Code restructure failed: missing block: B:70:0x0202, code lost:
    
        r5 = r9.u();
     */
    /* JADX WARN: Code restructure failed: missing block: B:71:0x0207, code lost:
    
        r5 = r5.d;
     */
    /* JADX WARN: Code restructure failed: missing block: B:72:0x0209, code lost:
    
        r14.a = new com.google.android.gms.internal.ads.C2810x1(r6, r13, r7, r5);
     */
    /* JADX WARN: Code restructure failed: missing block: B:73:0x0210, code lost:
    
        if (r12 != null) goto L77;
     */
    /* JADX WARN: Code restructure failed: missing block: B:74:0x0212, code lost:
    
        r45 = r1;
        r25 = r2;
        r30 = r3;
        r10 = r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:75:0x0219, code lost:
    
        r12 = r19;
        r4 = r20;
        r8 = r21;
     */
    /* JADX WARN: Code restructure failed: missing block: B:77:0x0225, code lost:
    
        r5 = r12.b;
        r6 = r5.p;
        r9 = r5.q;
        r12.e();
        r12.m = true;
        r13 = r8.w(1952867444);
     */
    /* JADX WARN: Code restructure failed: missing block: B:78:0x0238, code lost:
    
        if (r13 == null) goto L84;
     */
    /* JADX WARN: Code restructure failed: missing block: B:79:0x023a, code lost:
    
        r6 = r13.c;
        r6.j(r4);
     */
    /* JADX WARN: Code restructure failed: missing block: B:80:0x0247, code lost:
    
        if (com.google.android.gms.internal.ads.AbstractC2767w1.a(r6.u()) != 1) goto L82;
     */
    /* JADX WARN: Code restructure failed: missing block: B:81:0x0249, code lost:
    
        r6 = r6.I();
     */
    /* JADX WARN: Code restructure failed: missing block: B:82:0x024e, code lost:
    
        r6 = r6.H();
     */
    /* JADX WARN: Code restructure failed: missing block: B:83:0x0252, code lost:
    
        r5.p = r6;
        r5.q = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:84:0x0257, code lost:
    
        r5.p = r6;
        r5.q = r9;
     */
    /* JADX WARN: Code restructure failed: missing block: B:85:0x025b, code lost:
    
        r6 = r8.d;
        r7 = r6.size();
        r9 = 0;
        r10 = 0;
        r13 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:86:0x0264, code lost:
    
        r14 = 1953658222;
     */
    /* JADX WARN: Code restructure failed: missing block: B:87:0x0267, code lost:
    
        if (r13 >= r7) goto L337;
     */
    /* JADX WARN: Code restructure failed: missing block: B:88:0x0269, code lost:
    
        r4 = (com.google.android.gms.internal.ads.Mp) r6.get(r13);
        r25 = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:89:0x0275, code lost:
    
        if (r4.b != 1953658222) goto L93;
     */
    /* JADX WARN: Code restructure failed: missing block: B:90:0x0277, code lost:
    
        r2 = r4.c;
        r2.j(12);
        r2 = r2.C();
     */
    /* JADX WARN: Code restructure failed: missing block: B:91:0x0282, code lost:
    
        if (r2 <= 0) goto L93;
     */
    /* JADX WARN: Code restructure failed: missing block: B:92:0x0284, code lost:
    
        r10 = r10 + r2;
        r9 = r9 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:94:0x028c, code lost:
    
        r13 = r13 + 1;
        r2 = r25;
     */
    /* JADX WARN: Code restructure failed: missing block: B:95:0x0293, code lost:
    
        r25 = r2;
        r12.h = 0;
        r12.g = 0;
        r12.f = 0;
        r5.d = r9;
        r5.e = r10;
     */
    /* JADX WARN: Code restructure failed: missing block: B:96:0x02a3, code lost:
    
        if (r5.g.length >= r9) goto L98;
     */
    /* JADX WARN: Code restructure failed: missing block: B:97:0x02a5, code lost:
    
        r5.f = new long[r9];
        r5.g = new int[r9];
     */
    /* JADX WARN: Code restructure failed: missing block: B:99:0x02b0, code lost:
    
        if (r5.h.length >= r10) goto L101;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c(long r55) throws com.google.android.gms.internal.ads.zzaz {
        /*
            Method dump skipped, instructions count: 1917
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.B1.c(long):void");
    }

    @Override // com.google.android.gms.internal.ads.U
    public final boolean d(V v) {
        Bu buS;
        InterfaceC2294l0 interfaceC2294l0V = LA.v(v, true, false);
        if (interfaceC2294l0V != null) {
            buS = AbstractC2330lu.s(interfaceC2294l0V);
        } else {
            C2244ju c2244ju = AbstractC2330lu.b;
            buS = Bu.e;
        }
        this.o = buS;
        return interfaceC2294l0V == null;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void e(W w) {
        if ((this.b & 32) == 0) {
            w = new androidx.browser.customtabs.k(w, this.a);
        }
        this.F = w;
        int i = 0;
        this.p = 0;
        this.s = 0;
        InterfaceC2380n0[] interfaceC2380n0Arr = new InterfaceC2380n0[2];
        this.G = interfaceC2380n0Arr;
        InterfaceC2380n0[] interfaceC2380n0Arr2 = (InterfaceC2380n0[]) Yo.g(0, interfaceC2380n0Arr);
        this.G = interfaceC2380n0Arr2;
        for (InterfaceC2380n0 interfaceC2380n0 : interfaceC2380n0Arr2) {
            interfaceC2380n0.a(K);
        }
        List list = this.c;
        this.H = new InterfaceC2380n0[list.size()];
        int i2 = 100;
        while (i < this.H.length) {
            int i3 = i2 + 1;
            InterfaceC2380n0 interfaceC2380n0Q = this.F.q(i2, 3);
            interfaceC2380n0Q.a((C1832aG) list.get(i));
            this.H[i] = interfaceC2380n0Q;
            i++;
            i2 = i3;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:100:0x01d5, code lost:
    
        r21 = r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:101:0x01d7, code lost:
    
        r2 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:102:0x01d9, code lost:
    
        r2 = com.google.android.gms.internal.ads.LA.m(r8);
        r21 = r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:103:0x01eb, code lost:
    
        if ((r9 + r2) <= (r34.A - r34.B)) goto L105;
     */
    /* JADX WARN: Code restructure failed: missing block: B:105:0x01ee, code lost:
    
        r2 = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:106:0x01f0, code lost:
    
        r23 = r9;
        r31 = r14;
        ((com.google.android.gms.internal.ads.P) r35).h(r13, r4, r9 + r2, false);
        r15.j(0);
        r3 = r15.u();
     */
    /* JADX WARN: Code restructure failed: missing block: B:107:0x0204, code lost:
    
        if (r3 < 0) goto L464;
     */
    /* JADX WARN: Code restructure failed: missing block: B:108:0x0206, code lost:
    
        r34.C = r3 - r2;
        r3 = r34.e;
        r3.j(0);
        r5.e(4, r3);
        r34.B += 4;
        r34.A += r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:109:0x021f, code lost:
    
        if (r34.H.length <= 0) goto L128;
     */
    /* JADX WARN: Code restructure failed: missing block: B:110:0x0221, code lost:
    
        if (r2 <= 0) goto L128;
     */
    /* JADX WARN: Code restructure failed: missing block: B:111:0x0223, code lost:
    
        r3 = r13[4];
        r9 = r8.m;
        r14 = java.util.Objects.equals(r9, "video/avc");
        r3 = r8.j;
     */
    /* JADX WARN: Code restructure failed: missing block: B:112:0x022f, code lost:
    
        if (r14 != false) goto L117;
     */
    /* JADX WARN: Code restructure failed: missing block: B:114:0x0235, code lost:
    
        if (com.google.android.gms.internal.ads.AbstractC2514q5.g(r3, "video/avc") == false) goto L116;
     */
    /* JADX WARN: Code restructure failed: missing block: B:116:0x0238, code lost:
    
        r24 = r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:117:0x023c, code lost:
    
        r24 = r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:118:0x0241, code lost:
    
        if ((r3 & 31) == 6) goto L127;
     */
    /* JADX WARN: Code restructure failed: missing block: B:120:0x0247, code lost:
    
        if (java.util.Objects.equals(r9, "video/hevc") != false) goto L125;
     */
    /* JADX WARN: Code restructure failed: missing block: B:122:0x024d, code lost:
    
        if (com.google.android.gms.internal.ads.AbstractC2514q5.g(r3, "video/hevc") == false) goto L124;
     */
    /* JADX WARN: Code restructure failed: missing block: B:124:0x0250, code lost:
    
        r3 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:126:0x025a, code lost:
    
        if (((r3 & 126) >> 1) != 39) goto L124;
     */
    /* JADX WARN: Code restructure failed: missing block: B:127:0x025c, code lost:
    
        r3 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:128:0x025e, code lost:
    
        r24 = r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:129:0x0262, code lost:
    
        r34.E = r3;
        r5.e(r2, r15);
        r34.B += r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:130:0x026c, code lost:
    
        if (r2 <= 0) goto L466;
     */
    /* JADX WARN: Code restructure failed: missing block: B:132:0x0270, code lost:
    
        if (r34.D != false) goto L467;
     */
    /* JADX WARN: Code restructure failed: missing block: B:134:0x0276, code lost:
    
        if (com.google.android.gms.internal.ads.LA.K(r13, r2, r8) == false) goto L468;
     */
    /* JADX WARN: Code restructure failed: missing block: B:135:0x0278, code lost:
    
        r34.D = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:136:0x027b, code lost:
    
        r2 = r17;
        r3 = r21;
        r9 = r23;
        r4 = r24;
        r14 = r31;
     */
    /* JADX WARN: Code restructure failed: missing block: B:138:0x028e, code lost:
    
        throw com.google.android.gms.internal.ads.zzaz.a(null, "Invalid NAL length");
     */
    /* JADX WARN: Code restructure failed: missing block: B:139:0x028f, code lost:
    
        r21 = r3;
        r24 = r4;
        r23 = r9;
        r31 = r14;
     */
    /* JADX WARN: Code restructure failed: missing block: B:140:0x029a, code lost:
    
        if (r34.E == false) goto L155;
     */
    /* JADX WARN: Code restructure failed: missing block: B:141:0x029c, code lost:
    
        r3 = r34.g;
        r3.g(r2);
        ((com.google.android.gms.internal.ads.P) r35).h(r3.a, 0, r34.C, false);
        r5.e(r34.C, r3);
        r2 = r34.C;
        r9 = com.google.android.gms.internal.ads.LA.u(r3.c, r3.a);
        r3.j(0);
        r3.i(r9);
        r8 = r8.o;
     */
    /* JADX WARN: Code restructure failed: missing block: B:142:0x02c4, code lost:
    
        if (r8 != (-1)) goto L146;
     */
    /* JADX WARN: Code restructure failed: missing block: B:144:0x02c8, code lost:
    
        if (r10.c == 0) goto L152;
     */
    /* JADX WARN: Code restructure failed: missing block: B:145:0x02ca, code lost:
    
        r10.c = 0;
        r10.q(0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:147:0x02d2, code lost:
    
        if (r10.c == r8) goto L152;
     */
    /* JADX WARN: Code restructure failed: missing block: B:148:0x02d4, code lost:
    
        if (r8 < 0) goto L150;
     */
    /* JADX WARN: Code restructure failed: missing block: B:149:0x02d6, code lost:
    
        r4 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:150:0x02d8, code lost:
    
        r4 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:151:0x02d9, code lost:
    
        com.google.android.gms.internal.ads.AbstractC1795We.L(r4);
        r10.c = r8;
        r10.q(r8);
     */
    /* JADX WARN: Code restructure failed: missing block: B:152:0x02e1, code lost:
    
        r10.p(r11, r3);
     */
    /* JADX WARN: Code restructure failed: missing block: B:153:0x02ed, code lost:
    
        if ((r17.a() & 4) == 0) goto L156;
     */
    /* JADX WARN: Code restructure failed: missing block: B:154:0x02ef, code lost:
    
        r10.q(0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:155:0x02f3, code lost:
    
        r2 = r5.d(r35, r2, false);
     */
    /* JADX WARN: Code restructure failed: missing block: B:156:0x02f8, code lost:
    
        r34.B += r2;
        r34.C -= r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:157:0x0304, code lost:
    
        r0 = r17.a();
     */
    /* JADX WARN: Code restructure failed: missing block: B:158:0x030a, code lost:
    
        if (r34.D != false) goto L160;
     */
    /* JADX WARN: Code restructure failed: missing block: B:159:0x030c, code lost:
    
        r0 = r0 | 67108864;
     */
    /* JADX WARN: Code restructure failed: missing block: B:160:0x030f, code lost:
    
        r26 = r0;
        r0 = r17.c();
     */
    /* JADX WARN: Code restructure failed: missing block: B:161:0x0315, code lost:
    
        if (r0 == null) goto L163;
     */
    /* JADX WARN: Code restructure failed: missing block: B:162:0x0317, code lost:
    
        r29 = r0.c;
     */
    /* JADX WARN: Code restructure failed: missing block: B:163:0x031c, code lost:
    
        r29 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:164:0x031e, code lost:
    
        r24 = r11;
        r5.f(r24, r26, r34.A, 0, r29);
     */
    /* JADX WARN: Code restructure failed: missing block: B:166:0x032f, code lost:
    
        if (r31.isEmpty() != false) goto L459;
     */
    /* JADX WARN: Code restructure failed: missing block: B:167:0x0331, code lost:
    
        r0 = (com.google.android.gms.internal.ads.C2896z1) r31.removeFirst();
        r2 = r34.v;
        r7 = r0.c;
        r34.v = r2 - r7;
        r2 = r0.b;
        r3 = r0.a;
     */
    /* JADX WARN: Code restructure failed: missing block: B:168:0x0342, code lost:
    
        if (r2 == false) goto L170;
     */
    /* JADX WARN: Code restructure failed: missing block: B:169:0x0344, code lost:
    
        r3 = r3 + r24;
     */
    /* JADX WARN: Code restructure failed: missing block: B:170:0x0346, code lost:
    
        r4 = r3;
        r0 = r34.G;
        r2 = r0.length;
        r10 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:171:0x034b, code lost:
    
        if (r10 >= r2) goto L462;
     */
    /* JADX WARN: Code restructure failed: missing block: B:172:0x034d, code lost:
    
        r0[r10].f(r4, 1, r7, r34.v, null);
        r10 = r10 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:174:0x035d, code lost:
    
        if (r17.f() != false) goto L70;
     */
    /* JADX WARN: Code restructure failed: missing block: B:175:0x035f, code lost:
    
        r34.z = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:176:0x0364, code lost:
    
        r34.p = 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:177:0x0368, code lost:
    
        return 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x00ba, code lost:
    
        r3 = r34.p;
        r5 = r2.a;
        r9 = r2.b;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x00c6, code lost:
    
        if (r3 != 3) goto L79;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x00ca, code lost:
    
        if (r2.m != false) goto L50;
     */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x00cc, code lost:
    
        r3 = r2.d.d[r2.f];
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x00d5, code lost:
    
        r3 = r9.h[r2.f];
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x00db, code lost:
    
        r34.A = r3;
        r3 = r2.d.a.g.m;
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x00e9, code lost:
    
        if (java.util.Objects.equals(r3, "video/avc") != false) goto L54;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x00eb, code lost:
    
        java.util.Objects.equals(r3, "video/hevc");
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x00ee, code lost:
    
        r34.D = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x00f5, code lost:
    
        if (r2.f >= r2.i) goto L71;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x00f7, code lost:
    
        ((com.google.android.gms.internal.ads.P) r35).p(r34.A);
        r0 = r2.c();
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x0102, code lost:
    
        if (r0 != null) goto L59;
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:0x0105, code lost:
    
        r3 = r9.n;
        r0 = r0.d;
     */
    /* JADX WARN: Code restructure failed: missing block: B:60:0x0109, code lost:
    
        if (r0 == 0) goto L62;
     */
    /* JADX WARN: Code restructure failed: missing block: B:61:0x010b, code lost:
    
        r3.k(r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:62:0x010e, code lost:
    
        r0 = r2.f;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x0112, code lost:
    
        if (r9.k == false) goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x0118, code lost:
    
        if (r9.l[r0] == false) goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:66:0x011a, code lost:
    
        r3.k(r3.D() * 6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:68:0x0126, code lost:
    
        if (r2.f() != false) goto L70;
     */
    /* JADX WARN: Code restructure failed: missing block: B:69:0x0128, code lost:
    
        r34.z = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:72:0x0134, code lost:
    
        if (r2.d.a.h != 1) goto L74;
     */
    /* JADX WARN: Code restructure failed: missing block: B:73:0x0136, code lost:
    
        r34.A -= 8;
        ((com.google.android.gms.internal.ads.P) r35).p(8);
     */
    /* JADX WARN: Code restructure failed: missing block: B:75:0x0152, code lost:
    
        if ("audio/ac4".equals(r2.d.a.g.m) == false) goto L77;
     */
    /* JADX WARN: Code restructure failed: missing block: B:76:0x0154, code lost:
    
        r34.B = r2.b(r34.A, 7);
        r3 = r34.A;
        r12 = r34.i;
        com.google.android.gms.internal.ads.AbstractC1972di.u(r3, r12);
        r5.e(7, r12);
        r3 = r34.B + 7;
        r34.B = r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:77:0x016d, code lost:
    
        r3 = r2.b(r34.A, 0);
        r34.B = r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:78:0x0175, code lost:
    
        r34.A += r3;
        r34.p = 4;
        r34.C = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:79:0x017f, code lost:
    
        r3 = r2.d;
     */
    /* JADX WARN: Code restructure failed: missing block: B:80:0x0183, code lost:
    
        if (r2.m != false) goto L82;
     */
    /* JADX WARN: Code restructure failed: missing block: B:81:0x0185, code lost:
    
        r11 = r3.f[r2.f];
     */
    /* JADX WARN: Code restructure failed: missing block: B:82:0x018c, code lost:
    
        r11 = r9.i[r2.f];
     */
    /* JADX WARN: Code restructure failed: missing block: B:83:0x0192, code lost:
    
        r3 = r3.a;
        r9 = r3.k;
     */
    /* JADX WARN: Code restructure failed: missing block: B:84:0x0196, code lost:
    
        if (r9 != 0) goto L90;
     */
    /* JADX WARN: Code restructure failed: missing block: B:85:0x0198, code lost:
    
        r3 = r34.B;
        r4 = r34.A;
     */
    /* JADX WARN: Code restructure failed: missing block: B:86:0x019c, code lost:
    
        if (r3 >= r4) goto L458;
     */
    /* JADX WARN: Code restructure failed: missing block: B:87:0x019e, code lost:
    
        r34.B += r5.d(r35, r4 - r3, false);
     */
    /* JADX WARN: Code restructure failed: missing block: B:88:0x01a9, code lost:
    
        r17 = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:89:0x01ab, code lost:
    
        r31 = r14;
     */
    /* JADX WARN: Code restructure failed: missing block: B:90:0x01af, code lost:
    
        r15 = r34.f;
        r13 = r15.a;
        r13[0] = 0;
        r13[1] = 0;
        r13[r18] = 0;
        r4 = 4 - r9;
     */
    /* JADX WARN: Code restructure failed: missing block: B:91:0x01bd, code lost:
    
        r17 = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:92:0x01c3, code lost:
    
        if (r34.B >= r34.A) goto L463;
     */
    /* JADX WARN: Code restructure failed: missing block: B:93:0x01c5, code lost:
    
        r2 = r34.C;
        r8 = r3.g;
     */
    /* JADX WARN: Code restructure failed: missing block: B:94:0x01c9, code lost:
    
        if (r2 != 0) goto L139;
     */
    /* JADX WARN: Code restructure failed: missing block: B:96:0x01ce, code lost:
    
        if (r34.H.length > 0) goto L102;
     */
    /* JADX WARN: Code restructure failed: missing block: B:98:0x01d2, code lost:
    
        if (r34.D != false) goto L100;
     */
    @Override // com.google.android.gms.internal.ads.U
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int f(com.google.android.gms.internal.ads.V r35, androidx.compose.foundation.lazy.layout.C0429a r36) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 2058
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.B1.f(com.google.android.gms.internal.ads.V, androidx.compose.foundation.lazy.layout.a):int");
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void h(long j, long j2) {
        SparseArray sparseArray = this.d;
        int size = sparseArray.size();
        for (int i = 0; i < size; i++) {
            ((A1) sparseArray.valueAt(i)).e();
        }
        this.m.clear();
        this.v = 0;
        ((PriorityQueue) this.n.f).clear();
        this.w = j2;
        this.l.clear();
        this.p = 0;
        this.s = 0;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final /* synthetic */ List j() {
        return this.o;
    }
}
