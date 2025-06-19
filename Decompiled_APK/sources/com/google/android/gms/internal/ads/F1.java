package com.google.android.gms.internal.ads;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class F1 implements U, InterfaceC2122h0 {
    public int A;
    public final Z1 a;
    public final int b;
    public final Kn c;
    public final Kn d;
    public final Kn e;
    public final Kn f;
    public final ArrayDeque g;
    public final H1 h;
    public final ArrayList i;
    public Bu j;
    public int k;
    public int l;
    public long m;
    public int n;
    public Kn o;
    public int p;
    public int q;
    public int r;
    public int s;
    public boolean t;
    public boolean u;
    public W v;
    public E1[] w;
    public long[][] x;
    public int y;
    public long z;

    public F1() {
        this(Z1.P0, 16);
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x006e  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x00fb  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x0101  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x00ec A[EDGE_INSN: B:75:0x00ec->B:67:0x00ec BREAK  A[LOOP:1: B:31:0x0069->B:66:0x00e2], SYNTHETIC] */
    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.internal.ads.C2078g0 b(long r22) {
        /*
            Method dump skipped, instructions count: 268
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.F1.b(long):com.google.android.gms.internal.ads.g0");
    }

    @Override // com.google.android.gms.internal.ads.U
    public final boolean d(V v) {
        Bu buS;
        InterfaceC2294l0 interfaceC2294l0V = LA.v(v, false, false);
        if (interfaceC2294l0V != null) {
            buS = AbstractC2330lu.s(interfaceC2294l0V);
        } else {
            C2244ju c2244ju = AbstractC2330lu.b;
            buS = Bu.e;
        }
        this.j = buS;
        return interfaceC2294l0V == null;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void e(W w) {
        if ((this.b & 16) == 0) {
            w = new androidx.browser.customtabs.k(w, this.a);
        }
        this.v = w;
    }

    /* JADX WARN: Code restructure failed: missing block: B:100:0x01ea, code lost:
    
        r7.b = 3;
        r45.a = ((com.google.android.gms.internal.ads.G1) r11.get(0)).a;
     */
    /* JADX WARN: Code restructure failed: missing block: B:101:0x01f8, code lost:
    
        r29 = r6 == true ? 1 : 0;
        r3 = new com.google.android.gms.internal.ads.Kn(8);
        r44.o(0, r3.a, 8);
        r7.c = r3.v() + 8;
     */
    /* JADX WARN: Code restructure failed: missing block: B:102:0x0215, code lost:
    
        if (r3.u() == 1397048916) goto L104;
     */
    /* JADX WARN: Code restructure failed: missing block: B:103:0x0217, code lost:
    
        r45.a = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:104:0x021c, code lost:
    
        r45.a = r44.f() - (r7.c - 12);
        r7.b = 2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:105:0x022c, code lost:
    
        r29 = r6 == true ? 1 : 0;
        r3 = r44.j();
     */
    /* JADX WARN: Code restructure failed: missing block: B:106:0x0234, code lost:
    
        if (r3 == (-1)) goto L109;
     */
    /* JADX WARN: Code restructure failed: missing block: B:108:0x0238, code lost:
    
        if (r3 >= 8) goto L110;
     */
    /* JADX WARN: Code restructure failed: missing block: B:109:0x023a, code lost:
    
        r3 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:10:0x001f, code lost:
    
        r3 = r43.i;
        r7 = r43.h;
        r8 = r7.b;
     */
    /* JADX WARN: Code restructure failed: missing block: B:110:0x023d, code lost:
    
        r3 = r3 - 8;
     */
    /* JADX WARN: Code restructure failed: missing block: B:111:0x0240, code lost:
    
        r45.a = r3;
        r0 = r29;
        r7.b = r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:113:0x024c, code lost:
    
        if (r45.a != 0) goto L116;
     */
    /* JADX WARN: Code restructure failed: missing block: B:114:0x024e, code lost:
    
        i();
     */
    /* JADX WARN: Code restructure failed: missing block: B:115:0x0251, code lost:
    
        return r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:117:0x0255, code lost:
    
        r6 = r44.f();
        r4 = r43.p;
     */
    /* JADX WARN: Code restructure failed: missing block: B:118:0x025f, code lost:
    
        if (r4 != (-1)) goto L152;
     */
    /* JADX WARN: Code restructure failed: missing block: B:119:0x0261, code lost:
    
        r4 = -1;
        r10 = -1;
        r12 = 0;
        r13 = true;
        r14 = true;
        r15 = Long.MAX_VALUE;
        r17 = Long.MAX_VALUE;
        r31 = Long.MAX_VALUE;
     */
    /* JADX WARN: Code restructure failed: missing block: B:11:0x0025, code lost:
    
        if (r8 == 0) goto L105;
     */
    /* JADX WARN: Code restructure failed: missing block: B:120:0x027a, code lost:
    
        r8 = r43.w;
     */
    /* JADX WARN: Code restructure failed: missing block: B:121:0x027d, code lost:
    
        if (r12 >= r8.length) goto L404;
     */
    /* JADX WARN: Code restructure failed: missing block: B:122:0x027f, code lost:
    
        r8 = r8[r12];
        r9 = r8.e;
        r8 = r8.b;
     */
    /* JADX WARN: Code restructure failed: missing block: B:123:0x0287, code lost:
    
        if (r9 != r8.b) goto L125;
     */
    /* JADX WARN: Code restructure failed: missing block: B:125:0x028c, code lost:
    
        r35 = r8.c[r9];
        r3 = r43.x;
        r8 = com.google.android.gms.internal.ads.Yo.a;
        r8 = r3[r12][r9];
        r35 = r35 - r6;
     */
    /* JADX WARN: Code restructure failed: missing block: B:126:0x029e, code lost:
    
        if (r35 < 0) goto L129;
     */
    /* JADX WARN: Code restructure failed: missing block: B:128:0x02a2, code lost:
    
        if (r35 < 262144) goto L130;
     */
    /* JADX WARN: Code restructure failed: missing block: B:129:0x02a4, code lost:
    
        r3 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:12:0x0027, code lost:
    
        if (r8 == r6) goto L101;
     */
    /* JADX WARN: Code restructure failed: missing block: B:130:0x02a6, code lost:
    
        r3 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:131:0x02a7, code lost:
    
        if (r3 != false) goto L134;
     */
    /* JADX WARN: Code restructure failed: missing block: B:132:0x02a9, code lost:
    
        if (r13 != false) goto L137;
     */
    /* JADX WARN: Code restructure failed: missing block: B:133:0x02ab, code lost:
    
        r13 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:134:0x02ac, code lost:
    
        if (r3 != r13) goto L138;
     */
    /* JADX WARN: Code restructure failed: missing block: B:136:0x02b0, code lost:
    
        if (r35 >= r31) goto L138;
     */
    /* JADX WARN: Code restructure failed: missing block: B:137:0x02b2, code lost:
    
        r13 = r3;
        r17 = r8;
        r10 = r12;
        r31 = r35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:139:0x02ba, code lost:
    
        if (r8 >= r15) goto L124;
     */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x0029, code lost:
    
        r11 = r7.a;
        r24 = 8;
        r15 = 2192;
     */
    /* JADX WARN: Code restructure failed: missing block: B:140:0x02bc, code lost:
    
        r14 = r3;
        r15 = r8;
        r4 = r12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:141:0x02c0, code lost:
    
        r12 = r12 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:143:0x02c5, code lost:
    
        if (r15 == Long.MAX_VALUE) goto L148;
     */
    /* JADX WARN: Code restructure failed: missing block: B:144:0x02c7, code lost:
    
        if (r14 == false) goto L148;
     */
    /* JADX WARN: Code restructure failed: missing block: B:146:0x02cf, code lost:
    
        if (r17 < (r15 + 10485760)) goto L148;
     */
    /* JADX WARN: Code restructure failed: missing block: B:148:0x02d2, code lost:
    
        r4 = r10;
     */
    /* JADX WARN: Code restructure failed: missing block: B:149:0x02d3, code lost:
    
        r43.p = r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:14:0x0032, code lost:
    
        if (r8 == 2) goto L78;
     */
    /* JADX WARN: Code restructure failed: missing block: B:150:0x02d6, code lost:
    
        if (r4 != (-1)) goto L152;
     */
    /* JADX WARN: Code restructure failed: missing block: B:151:0x02d8, code lost:
    
        return -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:152:0x02d9, code lost:
    
        r3 = r43.w[r4];
        r12 = r3.c;
        r4 = r3.e;
        r8 = r3.b;
        r13 = r8.c[r4];
        r9 = r8.d;
        r10 = r9[r4];
        r31 = r5;
        r6 = (r13 - r6) + r43.q;
     */
    /* JADX WARN: Code restructure failed: missing block: B:153:0x02fa, code lost:
    
        if (r6 < 0) goto L156;
     */
    /* JADX WARN: Code restructure failed: missing block: B:155:0x02fe, code lost:
    
        if (r6 < 262144) goto L157;
     */
    /* JADX WARN: Code restructure failed: missing block: B:157:0x0304, code lost:
    
        r2 = r3.a;
     */
    /* JADX WARN: Code restructure failed: missing block: B:158:0x0309, code lost:
    
        if (r2.h != 1) goto L160;
     */
    /* JADX WARN: Code restructure failed: missing block: B:159:0x030b, code lost:
    
        r6 = r6 + 8;
        r10 = r10 - 8;
     */
    /* JADX WARN: Code restructure failed: missing block: B:15:0x0034, code lost:
    
        r18 = r44.f();
        r7 = (int) ((r44.j() - r44.f()) - r7.c);
        r12 = new com.google.android.gms.internal.ads.Kn(r7);
        r44.o(0, r12.a, r7);
        r0 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:160:0x030f, code lost:
    
        r44.g((int) r6);
        r5 = r2.g;
        r7 = r5.m;
     */
    /* JADX WARN: Code restructure failed: missing block: B:161:0x031d, code lost:
    
        if (java.util.Objects.equals(r7, "video/avc") != false) goto L163;
     */
    /* JADX WARN: Code restructure failed: missing block: B:162:0x031f, code lost:
    
        java.util.Objects.equals(r7, "video/hevc");
     */
    /* JADX WARN: Code restructure failed: missing block: B:163:0x0324, code lost:
    
        r43.t = true;
        r6 = r3.d;
        r2 = r2.k;
     */
    /* JADX WARN: Code restructure failed: missing block: B:164:0x032b, code lost:
    
        if (r2 == 0) goto L189;
     */
    /* JADX WARN: Code restructure failed: missing block: B:165:0x032d, code lost:
    
        r7 = r43.d;
        r11 = r7.a;
        r11[0] = 0;
        r11[1] = 0;
        r11[2] = 0;
        r13 = 4 - r2;
        r10 = r10 + r13;
     */
    /* JADX WARN: Code restructure failed: missing block: B:167:0x0340, code lost:
    
        if (r43.r >= r10) goto L405;
     */
    /* JADX WARN: Code restructure failed: missing block: B:168:0x0342, code lost:
    
        r14 = r43.s;
     */
    /* JADX WARN: Code restructure failed: missing block: B:169:0x0344, code lost:
    
        if (r14 != 0) goto L187;
     */
    /* JADX WARN: Code restructure failed: missing block: B:171:0x0348, code lost:
    
        if (r43.t != false) goto L176;
     */
    /* JADX WARN: Code restructure failed: missing block: B:172:0x034a, code lost:
    
        r16 = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:173:0x0356, code lost:
    
        if ((com.google.android.gms.internal.ads.LA.m(r5) + r2) > (r9[r4] - r43.q)) goto L175;
     */
    /* JADX WARN: Code restructure failed: missing block: B:174:0x0358, code lost:
    
        r2 = com.google.android.gms.internal.ads.LA.m(r5);
        r14 = r16 + r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:175:0x035f, code lost:
    
        r14 = r16;
        r2 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:176:0x0363, code lost:
    
        r16 = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:177:0x0366, code lost:
    
        r44.o(r13, r11, r14);
        r43.q += r14;
        r7.j(0);
        r15 = r7.u();
     */
    /* JADX WARN: Code restructure failed: missing block: B:178:0x0376, code lost:
    
        if (r15 < 0) goto L406;
     */
    /* JADX WARN: Code restructure failed: missing block: B:179:0x0378, code lost:
    
        r43.s = r15 - r2;
        r15 = r43.c;
        r15.j(0);
        r14 = r31;
        r12.e(r14, r15);
        r43.r += r14;
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x0057, code lost:
    
        if (r0 >= r11.size()) goto L391;
     */
    /* JADX WARN: Code restructure failed: missing block: B:180:0x038a, code lost:
    
        if (r2 <= 0) goto L408;
     */
    /* JADX WARN: Code restructure failed: missing block: B:181:0x038c, code lost:
    
        r12.e(r2, r7);
        r43.r += r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:182:0x0398, code lost:
    
        if (com.google.android.gms.internal.ads.LA.K(r11, r2, r5) == false) goto L409;
     */
    /* JADX WARN: Code restructure failed: missing block: B:183:0x039a, code lost:
    
        r43.t = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:184:0x039d, code lost:
    
        r2 = r16;
        r31 = 4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:186:0x03a9, code lost:
    
        throw com.google.android.gms.internal.ads.zzaz.a(null, "Invalid NAL length");
     */
    /* JADX WARN: Code restructure failed: missing block: B:187:0x03aa, code lost:
    
        r16 = r2;
        r14 = r12.d(r44, r14, false);
        r43.q += r14;
        r43.r += r14;
        r43.s -= r14;
     */
    /* JADX WARN: Code restructure failed: missing block: B:188:0x03c1, code lost:
    
        r16 = r10;
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:0x0059, code lost:
    
        r7 = (com.google.android.gms.internal.ads.G1) r11.get(r0);
        r12.j((int) (r7.a - r18));
        r12.k(r5);
        r13 = r12.v();
        r14 = java.nio.charset.StandardCharsets.UTF_8;
        r8 = r12.b(r13, r14);
     */
    /* JADX WARN: Code restructure failed: missing block: B:190:0x03ca, code lost:
    
        if ("audio/ac4".equals(r7) == false) goto L196;
     */
    /* JADX WARN: Code restructure failed: missing block: B:192:0x03ce, code lost:
    
        if (r43.r != 0) goto L194;
     */
    /* JADX WARN: Code restructure failed: missing block: B:193:0x03d0, code lost:
    
        com.google.android.gms.internal.ads.AbstractC1972di.u(r10, r11);
        r5 = 7;
        r12.e(7, r11);
        r43.r += 7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:194:0x03dd, code lost:
    
        r5 = 7;
     */
    /* JADX WARN: Code restructure failed: missing block: B:195:0x03de, code lost:
    
        r10 = r10 + r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:196:0x03e0, code lost:
    
        if (r6 == null) goto L412;
     */
    /* JADX WARN: Code restructure failed: missing block: B:197:0x03e2, code lost:
    
        r6.c(r44);
     */
    /* JADX WARN: Code restructure failed: missing block: B:198:0x03e5, code lost:
    
        r2 = r43.r;
     */
    /* JADX WARN: Code restructure failed: missing block: B:199:0x03e7, code lost:
    
        if (r2 >= r10) goto L411;
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:0x0078, code lost:
    
        switch(r8.hashCode()) {
            case -1711564334: goto L33;
            case -1332107749: goto L30;
            case -1251387154: goto L27;
            case -830665521: goto L24;
            case 1760745220: goto L21;
            default: goto L36;
        };
     */
    /* JADX WARN: Code restructure failed: missing block: B:200:0x03e9, code lost:
    
        r2 = r12.d(r44, r10 - r2, false);
        r43.q += r2;
        r43.r += r2;
        r43.s -= r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:201:0x0400, code lost:
    
        r13 = r8.f[r4];
        r0 = r8.g[r4];
     */
    /* JADX WARN: Code restructure failed: missing block: B:202:0x040a, code lost:
    
        if (r43.t != false) goto L204;
     */
    /* JADX WARN: Code restructure failed: missing block: B:203:0x040c, code lost:
    
        r0 = r0 | 67108864;
     */
    /* JADX WARN: Code restructure failed: missing block: B:204:0x040f, code lost:
    
        r15 = r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:205:0x0410, code lost:
    
        if (r6 == null) goto L209;
     */
    /* JADX WARN: Code restructure failed: missing block: B:206:0x0412, code lost:
    
        r6.b(r12, r13, r15, r16, 0, null);
     */
    /* JADX WARN: Code restructure failed: missing block: B:207:0x042b, code lost:
    
        if ((r4 + 1) != r8.b) goto L210;
     */
    /* JADX WARN: Code restructure failed: missing block: B:208:0x042d, code lost:
    
        r6.a(r12, null);
     */
    /* JADX WARN: Code restructure failed: missing block: B:209:0x0432, code lost:
    
        r12.f(r13, r15, r16, 0, null);
     */
    /* JADX WARN: Code restructure failed: missing block: B:210:0x043b, code lost:
    
        r3.e++;
        r43.p = -1;
        r43.q = 0;
        r43.r = 0;
        r43.s = 0;
        r43.t = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:211:0x044d, code lost:
    
        return 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:212:0x044e, code lost:
    
        r45.a = r13;
     */
    /* JADX WARN: Code restructure failed: missing block: B:213:0x0450, code lost:
    
        return 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:214:0x0451, code lost:
    
        r3 = r43.m - r43.n;
        r6 = r44.f() + r3;
        r9 = r43.o;
     */
    /* JADX WARN: Code restructure failed: missing block: B:215:0x045f, code lost:
    
        if (r9 == null) goto L243;
     */
    /* JADX WARN: Code restructure failed: missing block: B:216:0x0461, code lost:
    
        r44.o(r43.n, r9.a, (int) r3);
     */
    /* JADX WARN: Code restructure failed: missing block: B:217:0x046e, code lost:
    
        if (r43.l != 1718909296) goto L240;
     */
    /* JADX WARN: Code restructure failed: missing block: B:218:0x0470, code lost:
    
        r43.u = true;
        r9.j(8);
        r3 = r9.u();
     */
    /* JADX WARN: Code restructure failed: missing block: B:219:0x0482, code lost:
    
        if (r3 == 1751476579) goto L223;
     */
    /* JADX WARN: Code restructure failed: missing block: B:220:0x0484, code lost:
    
        if (r3 == 1903435808) goto L222;
     */
    /* JADX WARN: Code restructure failed: missing block: B:221:0x0486, code lost:
    
        r3 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:222:0x0488, code lost:
    
        r3 = 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:223:0x048a, code lost:
    
        r3 = 2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:224:0x048b, code lost:
    
        if (r3 == 0) goto L226;
     */
    /* JADX WARN: Code restructure failed: missing block: B:226:0x048e, code lost:
    
        r9.k(4);
     */
    /* JADX WARN: Code restructure failed: missing block: B:228:0x0496, code lost:
    
        if (r9.s() <= 0) goto L385;
     */
    /* JADX WARN: Code restructure failed: missing block: B:229:0x0498, code lost:
    
        r3 = r9.u();
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x0082, code lost:
    
        if (r8.equals("Super_SlowMotion_BGM") == false) goto L36;
     */
    /* JADX WARN: Code restructure failed: missing block: B:230:0x049c, code lost:
    
        if (r3 == 1751476579) goto L234;
     */
    /* JADX WARN: Code restructure failed: missing block: B:231:0x049e, code lost:
    
        if (r3 == 1903435808) goto L233;
     */
    /* JADX WARN: Code restructure failed: missing block: B:232:0x04a0, code lost:
    
        r3 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:233:0x04a2, code lost:
    
        r3 = 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:234:0x04a4, code lost:
    
        r3 = 2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:235:0x04a5, code lost:
    
        if (r3 == 0) goto L390;
     */
    /* JADX WARN: Code restructure failed: missing block: B:237:0x04a8, code lost:
    
        r3 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:238:0x04a9, code lost:
    
        r43.A = r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:239:0x04ab, code lost:
    
        r9 = false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:23:0x0084, code lost:
    
        r8 = 2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:241:0x04b1, code lost:
    
        if (r8.isEmpty() != false) goto L239;
     */
    /* JADX WARN: Code restructure failed: missing block: B:242:0x04b3, code lost:
    
        ((com.google.android.gms.internal.ads.C2840xp) r8.peek()).d.add(new com.google.android.gms.internal.ads.Mp(r43.l, r9));
     */
    /* JADX WARN: Code restructure failed: missing block: B:244:0x04c8, code lost:
    
        if (r43.u != false) goto L248;
     */
    /* JADX WARN: Code restructure failed: missing block: B:246:0x04cf, code lost:
    
        if (r43.l != 1835295092) goto L248;
     */
    /* JADX WARN: Code restructure failed: missing block: B:247:0x04d1, code lost:
    
        r43.A = 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:249:0x04d6, code lost:
    
        if (r3 >= 262144) goto L251;
     */
    /* JADX WARN: Code restructure failed: missing block: B:250:0x04d8, code lost:
    
        r44.g((int) r3);
     */
    /* JADX WARN: Code restructure failed: missing block: B:251:0x04dd, code lost:
    
        r45.a = r44.f() + r3;
        r9 = true;
     */
    /* JADX WARN: Code restructure failed: missing block: B:252:0x04e5, code lost:
    
        k(r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:253:0x04e8, code lost:
    
        if (r9 == false) goto L370;
     */
    /* JADX WARN: Code restructure failed: missing block: B:255:0x04ed, code lost:
    
        if (r43.k == 2) goto L371;
     */
    /* JADX WARN: Code restructure failed: missing block: B:256:0x04ef, code lost:
    
        return 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x008c, code lost:
    
        if (r8.equals("Super_SlowMotion_Deflickering_On") == false) goto L36;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x008e, code lost:
    
        r8 = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x0096, code lost:
    
        if (r8.equals("Super_SlowMotion_Data") == false) goto L36;
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x0098, code lost:
    
        r8 = r6 == true ? 1 : 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x00a0, code lost:
    
        if (r8.equals("Super_SlowMotion_Edit_Data") == false) goto L36;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x00a2, code lost:
    
        r8 = 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x00aa, code lost:
    
        if (r8.equals("SlowMotion_Data") == false) goto L36;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x00ac, code lost:
    
        r8 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x00ae, code lost:
    
        r8 = -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x00b0, code lost:
    
        if (r8 == 0) goto L48;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x00b2, code lost:
    
        if (r8 == r6) goto L47;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x00b4, code lost:
    
        if (r8 == 2) goto L46;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x00b6, code lost:
    
        if (r8 == 3) goto L45;
     */
    /* JADX WARN: Code restructure failed: missing block: B:413:?, code lost:
    
        return r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x00b8, code lost:
    
        if (r8 != r5) goto L392;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x00ba, code lost:
    
        r9 = 2820;
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x00c4, code lost:
    
        throw com.google.android.gms.internal.ads.zzaz.a(null, "Invalid SEF name");
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x00c5, code lost:
    
        r9 = 2819;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x00c8, code lost:
    
        r9 = 2817;
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x00cb, code lost:
    
        r9 = 2816;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x00ce, code lost:
    
        r9 = 2192;
     */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x00cf, code lost:
    
        r7 = r7.b - (r13 + 8);
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x00d4, code lost:
    
        if (r9 == 2192) goto L62;
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x00d8, code lost:
    
        if (r9 == 2816) goto L396;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x00dc, code lost:
    
        if (r9 == 2817) goto L397;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x00e0, code lost:
    
        if (r9 == 2819) goto L398;
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x00e4, code lost:
    
        if (r9 != 2820) goto L393;
     */
    /* JADX WARN: Code restructure failed: missing block: B:61:0x00ec, code lost:
    
        throw new java.lang.IllegalStateException();
     */
    /* JADX WARN: Code restructure failed: missing block: B:62:0x00ed, code lost:
    
        r9 = new java.util.ArrayList();
        r7 = com.google.android.gms.internal.ads.H1.e.k(r12.b(r7, r14));
        r13 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:64:0x0101, code lost:
    
        if (r13 >= r7.size()) goto L400;
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x0103, code lost:
    
        r8 = com.google.android.gms.internal.ads.H1.d.k((java.lang.CharSequence) r7.get(r13));
     */
    /* JADX WARN: Code restructure failed: missing block: B:66:0x0113, code lost:
    
        if (r8.size() != 3) goto L394;
     */
    /* JADX WARN: Code restructure failed: missing block: B:68:0x0116, code lost:
    
        r9.add(new com.google.android.gms.internal.ads.C1991e1(java.lang.Long.parseLong((java.lang.String) r8.get(0)), java.lang.Long.parseLong((java.lang.String) r8.get(r6 == true ? 1 : 0)), (r6 == true ? 1 : 0) << (java.lang.Integer.parseInt((java.lang.String) r8.get(2)) - 1)));
     */
    /* JADX WARN: Code restructure failed: missing block: B:69:0x0142, code lost:
    
        r13 = r13 + (r6 == true ? 1 : 0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:6:0x0015, code lost:
    
        r10 = 2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:70:0x0144, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:72:0x014a, code lost:
    
        throw com.google.android.gms.internal.ads.zzaz.a(r0, null);
     */
    /* JADX WARN: Code restructure failed: missing block: B:74:0x0150, code lost:
    
        throw com.google.android.gms.internal.ads.zzaz.a(null, null);
     */
    /* JADX WARN: Code restructure failed: missing block: B:75:0x0151, code lost:
    
        r3.add(new com.google.android.gms.internal.ads.C2035f1(r9));
     */
    /* JADX WARN: Code restructure failed: missing block: B:76:0x0159, code lost:
    
        r0 = r0 + (r6 == true ? 1 : 0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:77:0x015d, code lost:
    
        r45.a = 0;
        r0 = r6 == true ? 1 : 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:78:0x0164, code lost:
    
        r8 = r44.j();
        r3 = r7.c - 20;
        r5 = new com.google.android.gms.internal.ads.Kn(r3);
        r44.o(0, r5.a, r3);
        r0 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:7:0x0019, code lost:
    
        if (r7 == r6) goto L214;
     */
    /* JADX WARN: Code restructure failed: missing block: B:80:0x017a, code lost:
    
        if (r0 >= (r3 / 12)) goto L401;
     */
    /* JADX WARN: Code restructure failed: missing block: B:81:0x017c, code lost:
    
        r5.k(r10);
        r12 = r5.a;
        r13 = r5.b;
        r14 = r13 + 1;
        r5.b = r14;
        r29 = r6;
        r6 = r12[r13] & 255;
        r5.b = r13 + r10;
        r6 = (short) (r6 | ((r12[r14] & 255) << 8));
     */
    /* JADX WARN: Code restructure failed: missing block: B:82:0x0198, code lost:
    
        if (r6 == r15) goto L93;
     */
    /* JADX WARN: Code restructure failed: missing block: B:84:0x019c, code lost:
    
        if (r6 == 2816) goto L93;
     */
    /* JADX WARN: Code restructure failed: missing block: B:86:0x01a0, code lost:
    
        if (r6 == 2817) goto L91;
     */
    /* JADX WARN: Code restructure failed: missing block: B:88:0x01a6, code lost:
    
        if (r6 == 2819) goto L94;
     */
    /* JADX WARN: Code restructure failed: missing block: B:89:0x01a8, code lost:
    
        if (r6 == 2820) goto L94;
     */
    /* JADX WARN: Code restructure failed: missing block: B:90:0x01aa, code lost:
    
        r5.k(r24);
     */
    /* JADX WARN: Code restructure failed: missing block: B:94:0x01ba, code lost:
    
        r11.add(new com.google.android.gms.internal.ads.G1(r5.v(), (r8 - r7.c) - r5.v()));
     */
    /* JADX WARN: Code restructure failed: missing block: B:95:0x01d1, code lost:
    
        r0 = r0 + 1;
        r6 = r29;
        r10 = 2;
        r15 = 2192;
        r24 = 8;
     */
    /* JADX WARN: Code restructure failed: missing block: B:96:0x01db, code lost:
    
        r29 = r6;
     */
    /* JADX WARN: Code restructure failed: missing block: B:97:0x01e1, code lost:
    
        if (r11.isEmpty() == false) goto L100;
     */
    /* JADX WARN: Code restructure failed: missing block: B:98:0x01e3, code lost:
    
        r45.a = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:99:0x01e7, code lost:
    
        r0 = r29;
     */
    /* JADX WARN: Code restructure failed: missing block: B:9:0x001d, code lost:
    
        if (r7 == 2) goto L117;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r13v31 */
    /* JADX WARN: Type inference failed for: r13v32 */
    /* JADX WARN: Type inference failed for: r13v33 */
    @Override // com.google.android.gms.internal.ads.U
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int f(com.google.android.gms.internal.ads.V r44, androidx.compose.foundation.lazy.layout.C0429a r45) throws com.google.android.gms.internal.ads.zzaz {
        /*
            Method dump skipped, instructions count: 1730
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.F1.f(com.google.android.gms.internal.ads.V, androidx.compose.foundation.lazy.layout.a):int");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final boolean g() {
        return true;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void h(long j, long j2) {
        this.g.clear();
        this.n = 0;
        this.p = -1;
        this.q = 0;
        this.r = 0;
        this.s = 0;
        this.t = false;
        if (j == 0) {
            if (this.k != 3) {
                i();
                return;
            }
            H1 h1 = this.h;
            h1.a.clear();
            h1.b = 0;
            this.i.clear();
            return;
        }
        for (E1 e1 : this.w) {
            L1 l1 = e1.b;
            int iK = Yo.k(l1.f, j2, false);
            while (true) {
                if (iK < 0) {
                    iK = -1;
                    break;
                } else if ((l1.g[iK] & 1) != 0) {
                    break;
                } else {
                    iK--;
                }
            }
            if (iK == -1) {
                iK = l1.a(j2);
            }
            e1.e = iK;
            C2423o0 c2423o0 = e1.d;
            if (c2423o0 != null) {
                c2423o0.b = false;
                c2423o0.c = 0;
            }
        }
    }

    public final void i() {
        this.k = 0;
        this.n = 0;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final /* synthetic */ List j() {
        return this.j;
    }

    /* JADX WARN: Code restructure failed: missing block: B:101:0x0230, code lost:
    
        if (r3 != 14) goto L103;
     */
    /* JADX WARN: Code restructure failed: missing block: B:102:0x0232, code lost:
    
        r4 = "image/png";
        r3 = 14;
     */
    /* JADX WARN: Code restructure failed: missing block: B:103:0x023a, code lost:
    
        r4 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:104:0x023b, code lost:
    
        if (r4 != null) goto L106;
     */
    /* JADX WARN: Code restructure failed: missing block: B:105:0x023d, code lost:
    
        com.google.android.gms.internal.ads.AbstractC2096gb.J("MetadataUtil", "Unrecognized cover art flags: " + r3);
     */
    /* JADX WARN: Code restructure failed: missing block: B:106:0x024d, code lost:
    
        r6.k(4);
        r2 = r2 - 16;
        r0 = new byte[r2];
        r6.f(0, r0, r2);
        r0 = new com.google.android.gms.internal.ads.P0(r4, null, 3, r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:107:0x0263, code lost:
    
        com.google.android.gms.internal.ads.AbstractC2096gb.J("MetadataUtil", "Failed to parse cover art attribute");
        r0 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:109:0x0270, code lost:
    
        if (r4 != 1631670868) goto L111;
     */
    /* JADX WARN: Code restructure failed: missing block: B:110:0x0272, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.D(1631670868, "TPE2", r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:112:0x027d, code lost:
    
        if (r4 != 1936682605) goto L114;
     */
    /* JADX WARN: Code restructure failed: missing block: B:113:0x027f, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.D(1936682605, "TSOT", r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:115:0x028a, code lost:
    
        if (r4 != 1936679276) goto L117;
     */
    /* JADX WARN: Code restructure failed: missing block: B:116:0x028c, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.D(1936679276, "TSOA", r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:118:0x0297, code lost:
    
        if (r4 != 1936679282) goto L120;
     */
    /* JADX WARN: Code restructure failed: missing block: B:119:0x0299, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.D(1936679282, "TSOP", r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:121:0x02a4, code lost:
    
        if (r4 != 1936679265) goto L123;
     */
    /* JADX WARN: Code restructure failed: missing block: B:122:0x02a6, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.D(1936679265, "TSO2", r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:124:0x02b1, code lost:
    
        if (r4 != 1936679791) goto L126;
     */
    /* JADX WARN: Code restructure failed: missing block: B:125:0x02b3, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.D(1936679791, "TSOC", r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:127:0x02be, code lost:
    
        if (r4 != 1920233063) goto L129;
     */
    /* JADX WARN: Code restructure failed: missing block: B:128:0x02c0, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.t(1920233063, "ITUNESADVISORY", r6, false, false);
     */
    /* JADX WARN: Code restructure failed: missing block: B:130:0x02cd, code lost:
    
        if (r4 != 1885823344) goto L132;
     */
    /* JADX WARN: Code restructure failed: missing block: B:131:0x02cf, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.t(1885823344, "ITUNESGAPLESS", r6, false, true);
     */
    /* JADX WARN: Code restructure failed: missing block: B:133:0x02db, code lost:
    
        if (r4 != 1936683886) goto L135;
     */
    /* JADX WARN: Code restructure failed: missing block: B:134:0x02dd, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.D(1936683886, "TVSHOWSORT", r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:136:0x02e8, code lost:
    
        if (r4 != 1953919848) goto L138;
     */
    /* JADX WARN: Code restructure failed: missing block: B:137:0x02ea, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.D(1953919848, "TVSHOW", r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:139:0x02f5, code lost:
    
        if (r4 != 757935405) goto L165;
     */
    /* JADX WARN: Code restructure failed: missing block: B:140:0x02f7, code lost:
    
        r0 = null;
        r4 = null;
        r2 = r16;
        r3 = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:141:0x02fc, code lost:
    
        r12 = r6.b;
     */
    /* JADX WARN: Code restructure failed: missing block: B:142:0x02fe, code lost:
    
        if (r12 >= r15) goto L411;
     */
    /* JADX WARN: Code restructure failed: missing block: B:143:0x0300, code lost:
    
        r14 = r6.u();
        r5 = r6.u();
        r30 = r3;
        r6.k(4);
     */
    /* JADX WARN: Code restructure failed: missing block: B:144:0x0311, code lost:
    
        if (r5 != 1835360622) goto L148;
     */
    /* JADX WARN: Code restructure failed: missing block: B:145:0x0313, code lost:
    
        r4 = r6.a(r14 - 12);
     */
    /* JADX WARN: Code restructure failed: missing block: B:146:0x0319, code lost:
    
        r3 = r30;
     */
    /* JADX WARN: Code restructure failed: missing block: B:148:0x031d, code lost:
    
        r3 = r14 - 12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:149:0x0324, code lost:
    
        if (r5 != 1851878757) goto L151;
     */
    /* JADX WARN: Code restructure failed: missing block: B:150:0x0326, code lost:
    
        r0 = r6.a(r3);
     */
    /* JADX WARN: Code restructure failed: missing block: B:152:0x032e, code lost:
    
        if (r5 != 1684108385) goto L154;
     */
    /* JADX WARN: Code restructure failed: missing block: B:154:0x0331, code lost:
    
        r14 = r30;
     */
    /* JADX WARN: Code restructure failed: missing block: B:155:0x0333, code lost:
    
        if (r5 != 1684108385) goto L157;
     */
    /* JADX WARN: Code restructure failed: missing block: B:156:0x0335, code lost:
    
        r2 = r12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:157:0x0337, code lost:
    
        r6.k(r3);
        r3 = r14;
     */
    /* JADX WARN: Code restructure failed: missing block: B:158:0x033c, code lost:
    
        r30 = r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:159:0x033e, code lost:
    
        if (r4 == null) goto L80;
     */
    /* JADX WARN: Code restructure failed: missing block: B:160:0x0340, code lost:
    
        if (r0 == null) goto L80;
     */
    /* JADX WARN: Code restructure failed: missing block: B:162:0x0344, code lost:
    
        if (r2 != r16) goto L164;
     */
    /* JADX WARN: Code restructure failed: missing block: B:164:0x0348, code lost:
    
        r6.j(r2);
        r6.k(16);
        r0 = new com.google.android.gms.internal.ads.Y0(r4, r0, r6.a(r30 - 16));
     */
    /* JADX WARN: Code restructure failed: missing block: B:166:0x0363, code lost:
    
        r5 = r4 & 16777215;
     */
    /* JADX WARN: Code restructure failed: missing block: B:167:0x0368, code lost:
    
        if (r5 != 6516084) goto L173;
     */
    /* JADX WARN: Code restructure failed: missing block: B:168:0x036a, code lost:
    
        r2 = r6.u();
     */
    /* JADX WARN: Code restructure failed: missing block: B:169:0x0375, code lost:
    
        if (r6.u() != 1684108385) goto L171;
     */
    /* JADX WARN: Code restructure failed: missing block: B:170:0x0377, code lost:
    
        r6.k(8);
        r0 = r6.a(r2 - 16);
        r0 = new com.google.android.gms.internal.ads.T0("und", r0, r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:171:0x038c, code lost:
    
        com.google.android.gms.internal.ads.AbstractC2096gb.J("MetadataUtil", "Failed to parse comment attribute: ".concat(androidx.sqlite.db.b.t(r4)));
     */
    /* JADX WARN: Code restructure failed: missing block: B:172:0x0399, code lost:
    
        r0 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:174:0x03a2, code lost:
    
        if (r5 == 7233901) goto L206;
     */
    /* JADX WARN: Code restructure failed: missing block: B:176:0x03a7, code lost:
    
        if (r5 != 7631467) goto L178;
     */
    /* JADX WARN: Code restructure failed: missing block: B:179:0x03ae, code lost:
    
        if (r5 == 6516589) goto L205;
     */
    /* JADX WARN: Code restructure failed: missing block: B:181:0x03b3, code lost:
    
        if (r5 != 7828084) goto L183;
     */
    /* JADX WARN: Code restructure failed: missing block: B:184:0x03ba, code lost:
    
        if (r5 != 6578553) goto L186;
     */
    /* JADX WARN: Code restructure failed: missing block: B:185:0x03bc, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.D(r4, "TDRC", r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:187:0x03c7, code lost:
    
        if (r5 != 4280916) goto L189;
     */
    /* JADX WARN: Code restructure failed: missing block: B:188:0x03c9, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.D(r4, "TPE1", r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:190:0x03d3, code lost:
    
        if (r5 != 7630703) goto L192;
     */
    /* JADX WARN: Code restructure failed: missing block: B:191:0x03d5, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.D(r4, "TSSE", r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:193:0x03df, code lost:
    
        if (r5 != 6384738) goto L195;
     */
    /* JADX WARN: Code restructure failed: missing block: B:194:0x03e1, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.D(r4, "TALB", r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:196:0x03eb, code lost:
    
        if (r5 != 7108978) goto L198;
     */
    /* JADX WARN: Code restructure failed: missing block: B:197:0x03ed, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.D(r4, "USLT", r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:199:0x03f7, code lost:
    
        if (r5 != 6776174) goto L201;
     */
    /* JADX WARN: Code restructure failed: missing block: B:200:0x03f9, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.D(r4, "TCON", r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:202:0x0401, code lost:
    
        if (r5 != 6779504) goto L204;
     */
    /* JADX WARN: Code restructure failed: missing block: B:203:0x0403, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.D(r4, "TIT1", r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:204:0x040a, code lost:
    
        com.google.android.gms.internal.ads.AbstractC2096gb.p("Skipped unknown metadata entry: " + androidx.sqlite.db.b.t(r4));
     */
    /* JADX WARN: Code restructure failed: missing block: B:205:0x041f, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.D(r4, "TCOM", r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:206:0x0426, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.D(r4, "TIT2", r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:208:0x042f, code lost:
    
        if (r0 == null) goto L410;
     */
    /* JADX WARN: Code restructure failed: missing block: B:209:0x0431, code lost:
    
        r7.add(r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:210:0x0434, code lost:
    
        r5 = r28;
        r14 = r29;
        r2 = r31;
        r0 = r32;
        r16 = -1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:211:0x0446, code lost:
    
        r6.j(r15);
     */
    /* JADX WARN: Code restructure failed: missing block: B:212:0x0449, code lost:
    
        throw r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:213:0x044a, code lost:
    
        r32 = r0;
        r31 = r2;
        r28 = r5;
        r29 = r14;
     */
    /* JADX WARN: Code restructure failed: missing block: B:214:0x0459, code lost:
    
        if (r7.isEmpty() == false) goto L216;
     */
    /* JADX WARN: Code restructure failed: missing block: B:215:0x045b, code lost:
    
        r4 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:216:0x045d, code lost:
    
        r4 = new com.google.android.gms.internal.ads.K4(r7);
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x0178, code lost:
    
        r6.j(r7);
        r6.k(r12);
        r7 = new java.util.ArrayList();
     */
    /* JADX WARN: Code restructure failed: missing block: B:64:0x0183, code lost:
    
        r15 = r6.b;
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x0185, code lost:
    
        if (r15 >= r11) goto L408;
     */
    /* JADX WARN: Code restructure failed: missing block: B:66:0x0187, code lost:
    
        r15 = r6.u() + r15;
        r4 = r6.u();
        r28 = r5;
        r5 = (r4 >> 24) & 255;
        r29 = r14;
        r31 = r2;
        r32 = r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:67:0x01aa, code lost:
    
        if (r5 == 169) goto L166;
     */
    /* JADX WARN: Code restructure failed: missing block: B:69:0x01ae, code lost:
    
        if (r5 != 253) goto L71;
     */
    /* JADX WARN: Code restructure failed: missing block: B:72:0x01b5, code lost:
    
        if (r4 != 1735291493) goto L81;
     */
    /* JADX WARN: Code restructure failed: missing block: B:73:0x01b7, code lost:
    
        r3 = com.google.android.gms.internal.ads.X0.a(com.google.android.gms.internal.ads.AbstractC1795We.j(r6) - 1);
     */
    /* JADX WARN: Code restructure failed: missing block: B:74:0x01c1, code lost:
    
        if (r3 == null) goto L79;
     */
    /* JADX WARN: Code restructure failed: missing block: B:75:0x01c3, code lost:
    
        r0 = new com.google.android.gms.internal.ads.C1861b1("TCON", null, com.google.android.gms.internal.ads.AbstractC2330lu.s(r3));
     */
    /* JADX WARN: Code restructure failed: missing block: B:77:0x01d2, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:79:0x01d5, code lost:
    
        com.google.android.gms.internal.ads.AbstractC2096gb.J("MetadataUtil", "Failed to parse standard genre code");
     */
    /* JADX WARN: Code restructure failed: missing block: B:80:0x01da, code lost:
    
        r0 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:82:0x01df, code lost:
    
        if (r4 != 1684632427) goto L84;
     */
    /* JADX WARN: Code restructure failed: missing block: B:83:0x01e1, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.y(1684632427, "TPOS", r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:85:0x01eb, code lost:
    
        if (r4 != 1953655662) goto L87;
     */
    /* JADX WARN: Code restructure failed: missing block: B:86:0x01ed, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.y(1953655662, "TRCK", r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:88:0x01f7, code lost:
    
        if (r4 != 1953329263) goto L90;
     */
    /* JADX WARN: Code restructure failed: missing block: B:89:0x01f9, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.t(1953329263, "TBPM", r6, true, false);
     */
    /* JADX WARN: Code restructure failed: missing block: B:91:0x0206, code lost:
    
        if (r4 != 1668311404) goto L93;
     */
    /* JADX WARN: Code restructure failed: missing block: B:92:0x0208, code lost:
    
        r0 = com.google.android.gms.internal.ads.AbstractC1795We.t(1668311404, "TCMP", r6, true, true);
     */
    /* JADX WARN: Code restructure failed: missing block: B:94:0x0212, code lost:
    
        if (r4 != 1668249202) goto L108;
     */
    /* JADX WARN: Code restructure failed: missing block: B:95:0x0214, code lost:
    
        r2 = r6.u();
     */
    /* JADX WARN: Code restructure failed: missing block: B:96:0x021f, code lost:
    
        if (r6.u() != 1684108385) goto L107;
     */
    /* JADX WARN: Code restructure failed: missing block: B:97:0x0221, code lost:
    
        r3 = r6.u() & 16777215;
     */
    /* JADX WARN: Code restructure failed: missing block: B:98:0x0229, code lost:
    
        if (r3 != 13) goto L100;
     */
    /* JADX WARN: Code restructure failed: missing block: B:99:0x022b, code lost:
    
        r4 = "image/jpeg";
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:266:0x0530  */
    /* JADX WARN: Removed duplicated region for block: B:282:0x05d9  */
    /* JADX WARN: Removed duplicated region for block: B:286:0x0628  */
    /* JADX WARN: Removed duplicated region for block: B:358:0x0791 A[LOOP:13: B:356:0x078e->B:358:0x0791, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:362:0x07b6  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x0118  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x011a  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0129  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void k(long r36) {
        /*
            Method dump skipped, instructions count: 2104
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.F1.k(long):void");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final long zza() {
        return this.z;
    }

    public F1(Z1 z1, int i) {
        this.a = z1;
        this.b = i;
        C2244ju c2244ju = AbstractC2330lu.b;
        this.j = Bu.e;
        this.k = 0;
        this.h = new H1();
        this.i = new ArrayList();
        this.f = new Kn(16);
        this.g = new ArrayDeque();
        this.c = new Kn(LA.w);
        this.d = new Kn(6);
        this.e = new Kn();
        this.p = -1;
        this.v = W.O0;
        this.w = new E1[0];
    }
}
