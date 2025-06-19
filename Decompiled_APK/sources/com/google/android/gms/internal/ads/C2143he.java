package com.google.android.gms.internal.ads;

import android.content.Context;
import android.net.Uri;
import android.os.Handler;
import android.util.SparseBooleanArray;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/* renamed from: com.google.android.gms.internal.ads.he, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2143he implements FC, SD {
    public static final AtomicInteger u = new AtomicInteger(0);
    public static final AtomicInteger v = new AtomicInteger(0);
    public final Context a;
    public final C1968de b;
    public final VF c;
    public final C1668Bd d;
    public final WeakReference e;
    public final As f;
    public PD g;
    public ByteBuffer h;
    public boolean i;
    public InterfaceC2828xd j;
    public int k;
    public int l;
    public long m;
    public final String n;
    public final int o;
    public Integer q;
    public final ArrayList r;
    public volatile C2011ee s;
    public final Object p = new Object();
    public final HashSet t = new HashSet();

    /* JADX WARN: Removed duplicated region for block: B:24:0x010f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public C2143he(android.content.Context r5, com.google.android.gms.internal.ads.C1668Bd r6, com.google.android.gms.internal.ads.InterfaceC2529qe r7, java.lang.Integer r8) {
        /*
            Method dump skipped, instructions count: 395
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2143he.<init>(android.content.Context, com.google.android.gms.internal.ads.Bd, com.google.android.gms.internal.ads.qe, java.lang.Integer):void");
    }

    public static JE[] t(C2143he c2143he, Handler handler, SurfaceHolderCallbackC2091gD surfaceHolderCallbackC2091gD, SurfaceHolderCallbackC2091gD surfaceHolderCallbackC2091gD2) {
        Context context = c2143he.a;
        C2394nE c2394nE = new C2394nE(context);
        AbstractC1795We.L(!c2394nE.c);
        c2394nE.c = true;
        if (c2394nE.d == null) {
            C2694uE c2694uE = new C2694uE();
            c2694uE.m = 0;
            c2694uE.o = 0;
            c2694uE.p = 0;
            byte[] bArr = Yo.b;
            c2694uE.n = bArr;
            c2694uE.q = bArr;
            C1926cg c1926cg = new C1926cg();
            c1926cg.c = 1.0f;
            c1926cg.d = 1.0f;
            C2229jf c2229jf = C2229jf.e;
            c1926cg.e = c2229jf;
            c1926cg.f = c2229jf;
            c1926cg.g = c2229jf;
            c1926cg.h = c2229jf;
            ByteBuffer byteBuffer = InterfaceC1688Ef.a;
            c1926cg.k = byteBuffer;
            c1926cg.l = byteBuffer.asShortBuffer();
            c1926cg.m = byteBuffer;
            c1926cg.b = -1;
            Iw iw = new Iw();
            InterfaceC1688Ef[] interfaceC1688EfArr = {c2694uE, c1926cg};
            iw.c = interfaceC1688EfArr;
            System.arraycopy(new InterfaceC1688Ef[0], 0, interfaceC1688EfArr, 0, 0);
            iw.a = c2694uE;
            iw.b = c1926cg;
            c2394nE.d = iw;
        }
        if (c2394nE.e == null) {
            c2394nE.e = new C2351mE(c2394nE.a);
        }
        C2651tE c2651tE = new C2651tE(context, new Wr(context), handler, surfaceHolderCallbackC2091gD2, new C2608sE(c2394nE));
        C2250k c2250k = new C2250k(context);
        c2250k.d = handler;
        c2250k.e = surfaceHolderCallbackC2091gD;
        AbstractC1795We.L(!c2250k.b);
        Handler handler2 = c2250k.d;
        AbstractC1795We.L((handler2 == null && c2250k.e == null) || !(handler2 == null || c2250k.e == null));
        c2250k.b = true;
        return new JE[]{c2651tE, new C2293l(c2250k)};
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final void a(IOException iOException) {
        InterfaceC2828xd interfaceC2828xd = this.j;
        if (interfaceC2828xd != null) {
            if (this.d.j) {
                interfaceC2828xd.g(iOException);
            } else {
                interfaceC2828xd.h("onLoadError", iOException);
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.google.android.gms.internal.ads.FC
    public final void b(AbstractC2802wu abstractC2802wu, C2891yx c2891yx, boolean z) {
        if (abstractC2802wu instanceof InterfaceC2648tB) {
            synchronized (this.p) {
                this.r.add((InterfaceC2648tB) abstractC2802wu);
            }
        } else if (abstractC2802wu instanceof C2011ee) {
            this.s = (C2011ee) abstractC2802wu;
            InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) this.e.get();
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.T1)).booleanValue() && interfaceC2529qe != null && this.s.n) {
                HashMap map = new HashMap();
                map.put("gcacheHit", String.valueOf(this.s.p));
                map.put("gcacheDownloaded", String.valueOf(this.s.q));
                com.google.android.gms.ads.internal.util.F.l.post(new Qv(15, interfaceC2529qe, map));
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.FC
    public final void c(C2891yx c2891yx, boolean z) {
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final void d(C1740Nd c1740Nd) {
        InterfaceC2828xd interfaceC2828xd = this.j;
        if (interfaceC2828xd != null) {
            interfaceC2828xd.i(c1740Nd.a, c1740Nd.b);
        }
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final void e() {
        InterfaceC2828xd interfaceC2828xd = this.j;
        if (interfaceC2828xd != null) {
            interfaceC2828xd.d();
        }
    }

    @Override // com.google.android.gms.internal.ads.FC
    public final void f(C2891yx c2891yx, boolean z, int i) {
        this.k += i;
    }

    public final void finalize() {
        u.decrementAndGet();
        if (com.google.android.gms.ads.internal.util.A.m()) {
            com.google.android.gms.ads.internal.util.A.l("SimpleExoPlayerAdapter finalize ".concat(toString()));
        }
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final void g(int i) {
        InterfaceC2828xd interfaceC2828xd = this.j;
        if (interfaceC2828xd != null) {
            interfaceC2828xd.a(i);
        }
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final /* synthetic */ void h(RD rd, int i, long j) {
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final void i(C1832aG c1832aG) {
        InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) this.e.get();
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.T1)).booleanValue() || interfaceC2529qe == null) {
            return;
        }
        HashMap map = new HashMap();
        String str = c1832aG.l;
        if (str != null) {
            map.put("audioMime", str);
        }
        String str2 = c1832aG.m;
        if (str2 != null) {
            map.put("audioSampleMime", str2);
        }
        String str3 = c1832aG.j;
        if (str3 != null) {
            map.put("audioCodec", str3);
        }
        interfaceC2529qe.j("onMetadataEvent", map);
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final /* synthetic */ void j(PD pd, Fp fp) {
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final /* synthetic */ void k(QC qc) {
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final void k0(int i) {
        this.l += i;
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final void l(C1832aG c1832aG) {
        InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) this.e.get();
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.T1)).booleanValue() || interfaceC2529qe == null) {
            return;
        }
        HashMap map = new HashMap();
        map.put("frameRate", String.valueOf(c1832aG.v));
        map.put("bitRate", String.valueOf(c1832aG.i));
        map.put("resolution", c1832aG.t + "x" + c1832aG.u);
        String str = c1832aG.l;
        if (str != null) {
            map.put("videoMime", str);
        }
        String str2 = c1832aG.m;
        if (str2 != null) {
            map.put("videoSampleMime", str2);
        }
        String str3 = c1832aG.j;
        if (str3 != null) {
            map.put("videoCodec", str3);
        }
        interfaceC2529qe.j("onMetadataEvent", map);
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final void m(zzba zzbaVar) {
        InterfaceC2828xd interfaceC2828xd = this.j;
        if (interfaceC2828xd != null) {
            interfaceC2828xd.h("onPlayerError", zzbaVar);
        }
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final /* synthetic */ void n(int i) {
    }

    @Override // com.google.android.gms.internal.ads.SD
    public final /* synthetic */ void o(RD rd, androidx.compose.animation.core.S0 s0) {
    }

    public final long p() {
        if (this.s != null && this.s.o) {
            C2011ee c2011ee = this.s;
            if (c2011ee.m != null) {
                AtomicLong atomicLong = c2011ee.t;
                if (atomicLong.get() != -1) {
                    return atomicLong.get();
                }
                synchronized (c2011ee) {
                    try {
                        if (c2011ee.s == null) {
                            c2011ee.s = AbstractC2270kd.a.d(new Q4(c2011ee, 3));
                        }
                    } finally {
                    }
                }
                if (c2011ee.s.isDone()) {
                    try {
                        c2011ee.t.compareAndSet(-1L, ((Long) c2011ee.s.get()).longValue());
                        return c2011ee.t.get();
                    } catch (InterruptedException | ExecutionException unused) {
                    }
                }
            }
            return -1L;
        }
        synchronized (this.p) {
            while (true) {
                ArrayList arrayList = this.r;
                if (!arrayList.isEmpty()) {
                    long j = this.m;
                    Map mapZze = ((InterfaceC2648tB) arrayList.remove(0)).zze();
                    long j2 = 0;
                    if (mapZze != null) {
                        Iterator it2 = mapZze.entrySet().iterator();
                        while (true) {
                            if (!it2.hasNext()) {
                                break;
                            }
                            Map.Entry entry = (Map.Entry) it2.next();
                            if (entry != null) {
                                try {
                                    if (entry.getKey() != null && AbstractC2543qs.v((CharSequence) entry.getKey(), "content-length") && entry.getValue() != null && ((List) entry.getValue()).get(0) != null) {
                                        j2 = Long.parseLong((String) ((List) entry.getValue()).get(0));
                                        break;
                                    }
                                } catch (NumberFormatException unused2) {
                                    continue;
                                }
                            }
                        }
                    }
                    this.m = j + j2;
                }
            }
        }
        return this.m;
    }

    public final void q(Uri[] uriArr, ByteBuffer byteBuffer, boolean z) {
        Object c2438oF;
        if (this.g != null) {
            this.h = byteBuffer;
            this.i = z;
            int length = uriArr.length;
            if (length == 1) {
                c2438oF = s(uriArr[0]);
            } else {
                NE[] neArr = new NE[length];
                for (int i = 0; i < uriArr.length; i++) {
                    neArr[i] = s(uriArr[i]);
                }
                c2438oF = new C2438oF(new TD(16), neArr);
            }
            PD pd = this.g;
            pd.d.a();
            C2221jD c2221jD = pd.c;
            c2221jD.U();
            List listSingletonList = Collections.singletonList(c2438oF);
            c2221jD.U();
            c2221jD.U();
            c2221jD.m1(c2221jD.d1);
            c2221jD.y1();
            c2221jD.B++;
            ArrayList arrayList = c2221jD.p;
            if (!arrayList.isEmpty()) {
                int size = arrayList.size();
                for (int i2 = size - 1; i2 >= 0; i2--) {
                    arrayList.remove(i2);
                }
                CF cf = c2221jD.h1;
                int[] iArr = cf.b;
                int[] iArr2 = new int[iArr.length - size];
                int i3 = 0;
                for (int i4 = 0; i4 < iArr.length; i4++) {
                    int i5 = iArr[i4];
                    if (i5 < 0 || i5 >= size) {
                        int i6 = i4 - i3;
                        if (i5 >= 0) {
                            i5 -= size;
                        }
                        iArr2[i6] = i5;
                    } else {
                        i3++;
                    }
                }
                c2221jD.h1 = new CF(iArr2, new Random(cf.a.nextLong()));
            }
            ArrayList arrayList2 = new ArrayList();
            for (int i7 = 0; i7 < listSingletonList.size(); i7++) {
                FD fd = new FD((NE) listSingletonList.get(i7), c2221jD.q);
                arrayList2.add(fd);
                arrayList.add(i7, new C2179iD(fd.b, fd.a));
            }
            c2221jD.h1 = c2221jD.h1.a(arrayList2.size());
            LD ld = new LD(arrayList, c2221jD.h1);
            boolean zO = ld.o();
            int i8 = ld.d;
            if (!zO && i8 < 0) {
                throw new zzaa();
            }
            int iG = ld.g(false);
            GD gdS1 = c2221jD.s1(c2221jD.d1, ld, c2221jD.q1(ld, iG, -9223372036854775807L));
            int i9 = gdS1.e;
            if (iG != -1 && i9 != 1) {
                i9 = 4;
                if (!ld.o() && iG < i8) {
                    i9 = 2;
                }
            }
            GD gdR1 = C2221jD.r1(gdS1, i9);
            long jT = Yo.t(-9223372036854775807L);
            CF cf2 = c2221jD.h1;
            C2436oD c2436oD = c2221jD.l;
            c2436oD.getClass();
            c2436oD.h.a(17, new C2350mD(arrayList2, cf2, iG, jT)).a();
            c2221jD.x1(gdR1, 0, (c2221jD.d1.b.a.equals(gdR1.b.a) || c2221jD.d1.a.o()) ? false : true, 4, c2221jD.o1(gdR1), -1);
            PD pd2 = this.g;
            pd2.d.a();
            C2221jD c2221jD2 = pd2.c;
            c2221jD2.U();
            GD gd = c2221jD2.d1;
            if (gd.e == 1) {
                GD gdE = gd.e(null);
                GD gdR12 = C2221jD.r1(gdE, true != gdE.a.o() ? 2 : 4);
                c2221jD2.B++;
                Bo bo = c2221jD2.l.h;
                bo.getClass();
                C2367mo c2367moE = Bo.e();
                c2367moE.a = bo.a.obtainMessage(29);
                c2367moE.a();
                c2221jD2.x1(gdR12, 1, false, 5, -9223372036854775807L, -1);
            }
            v.incrementAndGet();
        }
    }

    public final void r(boolean z) {
        PF pf;
        boolean zEquals;
        if (this.g == null) {
            return;
        }
        int i = 0;
        while (true) {
            PD pd = this.g;
            pd.d.a();
            C2221jD c2221jD = pd.c;
            c2221jD.U();
            int length = c2221jD.h.length;
            if (i >= 2) {
                return;
            }
            VF vf = this.c;
            synchronized (vf.c) {
                pf = vf.e;
            }
            pf.getClass();
            OF of = new OF(pf);
            boolean z2 = !z;
            SparseBooleanArray sparseBooleanArray = of.B;
            if (sparseBooleanArray.get(i) != z2) {
                if (z) {
                    sparseBooleanArray.delete(i);
                } else {
                    sparseBooleanArray.put(i, true);
                }
            }
            PF pf2 = new PF(of);
            synchronized (vf.c) {
                zEquals = vf.e.equals(pf2);
                vf.e = pf2;
            }
            if (!zEquals) {
                if (pf2.x && vf.d == null) {
                    AbstractC2096gb.J("DefaultTrackSelector", "Audio channel count constraints cannot be applied without reference to Context. Build the track selector instance with one of the non-deprecated constructors that take a Context argument.");
                }
                C2436oD c2436oD = vf.a;
                if (c2436oD != null) {
                    c2436oD.h.c(10);
                }
            }
            i++;
        }
    }

    public final C2781wF s(Uri uri) {
        C2244ju c2244ju = AbstractC2330lu.b;
        Bu bu = Bu.e;
        List list = Collections.EMPTY_LIST;
        Bu bu2 = Bu.e;
        E2 e2 = E2.a;
        C2640t3 c2640t3 = new C2640t3("", new I0(), uri != null ? new V1(uri, bu2) : null, new D1(), C2082g4.B);
        int i = this.d.f;
        As as = this.f;
        as.a = i;
        c2640t3.b.getClass();
        return new C2781wF(c2640t3, (InterfaceC2589rw) as.b, (C2883yp) as.c, (TD) as.d, as.a);
    }

    public final long u() {
        if (this.s != null && this.s.o && this.s.p) {
            return Math.min(this.k, this.s.r);
        }
        return 0L;
    }
}
