package com.google.android.gms.internal.ads;

import android.content.Context;
import android.media.MediaCodecInfo;
import android.media.MediaFormat;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.SystemClock;
import android.os.Trace;
import android.util.SparseArray;
import android.view.Surface;
import androidx.core.app.NotificationManagerCompat;
import com.amazon.device.ads.DtbConstants;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.PriorityQueue;

/* renamed from: com.google.android.gms.internal.ads.l, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2293l extends JE {
    public static final int[] q2 = {1920, 1600, 1440, 1280, 960, 854, 640, 540, DtbConstants.DEFAULT_PLAYER_HEIGHT};
    public static boolean r2;
    public static boolean s2;
    public final Context F1;
    public final boolean G1;
    public final Fi H1;
    public final boolean I1;
    public final C2722v J1;
    public final C2679u K1;
    public final long L1;
    public final PriorityQueue M1;
    public com.bumptech.glide.load.engine.cache.f N1;
    public boolean O1;
    public boolean P1;
    public E Q1;
    public boolean R1;
    public int S1;
    public List T1;
    public Surface U1;
    public zzaax V1;
    public Pn W1;
    public boolean X1;
    public int Y1;
    public int Z1;
    public long a2;
    public int b2;
    public int c2;
    public int d2;
    public long e2;
    public int f2;
    public long g2;
    public C1740Nd h2;
    public C1740Nd i2;
    public int j2;
    public int k2;
    public InterfaceC2636t l2;
    public long m2;
    public long n2;
    public boolean o2;
    public boolean p2;

    public C2293l(C2250k c2250k) {
        super(2, c2250k.c, 30.0f);
        Context applicationContext = c2250k.a.getApplicationContext();
        this.F1 = applicationContext;
        this.Q1 = null;
        this.H1 = new Fi(c2250k.d, c2250k.e);
        this.G1 = this.Q1 == null;
        this.J1 = new C2722v(applicationContext, this);
        this.K1 = new C2679u();
        this.I1 = "NVIDIA".equals(Build.MANUFACTURER);
        this.W1 = Pn.c;
        this.Y1 = 1;
        this.Z1 = 0;
        this.h2 = C1740Nd.d;
        this.k2 = 0;
        this.i2 = null;
        this.j2 = NotificationManagerCompat.IMPORTANCE_UNSPECIFIED;
        this.m2 = -9223372036854775807L;
        this.n2 = -9223372036854775807L;
        this.M1 = new PriorityQueue();
        this.L1 = -9223372036854775807L;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:38:0x007b  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0080 A[FALL_THROUGH] */
    /* JADX WARN: Removed duplicated region for block: B:44:0x0086  */
    /* JADX WARN: Removed duplicated region for block: B:507:0x0789  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x00fc  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final boolean o0(java.lang.String r17) {
        /*
            Method dump skipped, instructions count: 2924
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2293l.o0(java.lang.String):boolean");
    }

    public static List q0(Context context, C1 c1, C1832aG c1832aG, boolean z, boolean z2) {
        List listB;
        String str = c1832aG.m;
        if (str == null) {
            return Bu.e;
        }
        if ("video/dolby-vision".equals(str) && !AbstractC1972di.i(context)) {
            String strA = ME.a(c1832aG);
            if (strA == null) {
                listB = Bu.e;
            } else {
                c1.getClass();
                listB = ME.b(strA, z, z2);
            }
            if (!listB.isEmpty()) {
                return listB;
            }
        }
        return ME.c(c1, c1832aG, z, z2);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0041  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x008b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static int r0(com.google.android.gms.internal.ads.HE r11, com.google.android.gms.internal.ads.C1832aG r12) {
        /*
            Method dump skipped, instructions count: 266
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2293l.r0(com.google.android.gms.internal.ads.HE, com.google.android.gms.internal.ads.aG):int");
    }

    public static int s0(HE he, C1832aG c1832aG) {
        int i = c1832aG.n;
        if (i == -1) {
            return r0(he, c1832aG);
        }
        List list = c1832aG.p;
        int size = list.size();
        int length = 0;
        for (int i2 = 0; i2 < size; i2++) {
            length += ((byte[]) list.get(i2)).length;
        }
        return i + length;
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void A(C1832aG c1832aG) throws zzik {
        E e = this.Q1;
        if (e == null || e.T()) {
            return;
        }
        try {
            e.L(c1832aG);
        } catch (zzacg e2) {
            throw b0(e2, c1832aG, false, 7000);
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final boolean B(MC mc) {
        if (!l() && !mc.s(536870912)) {
            long j = this.n2;
            if (j != -9223372036854775807L && j - (mc.g - this.z1.c) > 100000 && !mc.s(1073741824)) {
                boolean z = mc.g < this.l;
                if ((z || this.p2) && !mc.s(268435456) && mc.s(67108864)) {
                    mc.v();
                    if (z) {
                        this.y1.d++;
                        return true;
                    }
                    if (this.p2) {
                        this.M1.add(Long.valueOf(mc.g));
                    }
                    return true;
                }
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final boolean C(HE he) {
        return v0(he);
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final int I(C1 c1, C1832aG c1832aG) {
        boolean z;
        String str = c1832aG.m;
        if (!AbstractC2514q5.j(str)) {
            return 128;
        }
        int i = 0;
        boolean z2 = c1832aG.q != null;
        Context context = this.F1;
        List listQ0 = q0(context, c1, c1832aG, z2, false);
        if (z2 && listQ0.isEmpty()) {
            listQ0 = q0(context, c1, c1832aG, false, false);
        }
        if (listQ0.isEmpty()) {
            return 129;
        }
        if (c1832aG.J != 0) {
            return 130;
        }
        HE he = (HE) listQ0.get(0);
        boolean zC = he.c(c1832aG);
        if (zC) {
            z = true;
        } else {
            for (int i2 = 1; i2 < listQ0.size(); i2++) {
                HE he2 = (HE) listQ0.get(i2);
                if (he2.c(c1832aG)) {
                    zC = true;
                    z = false;
                    he = he2;
                    break;
                }
            }
            z = true;
        }
        int i3 = true != zC ? 3 : 4;
        int i4 = true != he.d(c1832aG) ? 8 : 16;
        int i5 = true != he.g ? 0 : 64;
        int i6 = true != z ? 0 : 128;
        if ("video/dolby-vision".equals(str) && !AbstractC1972di.i(context)) {
            i6 = 256;
        }
        if (zC) {
            List listQ02 = q0(context, c1, c1832aG, z2, true);
            if (!listQ02.isEmpty()) {
                HashMap map = ME.a;
                ArrayList arrayList = new ArrayList(listQ02);
                Collections.sort(arrayList, new Cr(new UD(c1832aG), 1));
                HE he3 = (HE) arrayList.get(0);
                if (he3.c(c1832aG) && he3.d(c1832aG)) {
                    i = 32;
                }
            }
        }
        return i3 | i4 | i | i5 | i6;
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final RC J(HE he, C1832aG c1832aG, C1832aG c1832aG2) {
        int i;
        int i2;
        RC rcA = he.a(c1832aG, c1832aG2);
        com.bumptech.glide.load.engine.cache.f fVar = this.N1;
        fVar.getClass();
        int i3 = c1832aG2.t;
        int i4 = fVar.a;
        int i5 = rcA.e;
        if (i3 > i4 || c1832aG2.u > fVar.b) {
            i5 |= 256;
        }
        if (s0(he, c1832aG2) > fVar.c) {
            i5 |= 64;
        }
        if (i5 != 0) {
            i = 0;
            i2 = i5;
        } else {
            i = rcA.d;
            i2 = 0;
        }
        return new RC(he.a, c1832aG, c1832aG2, i, i2);
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final RC K(Ps ps) throws Throwable {
        RC rcK = super.K(ps);
        C1832aG c1832aG = (C1832aG) ps.a;
        c1832aG.getClass();
        Fi fi = this.H1;
        Handler handler = (Handler) fi.b;
        if (handler != null) {
            handler.post(new C(fi, c1832aG, rcK, 0));
        }
        return rcK;
    }

    /* JADX WARN: Code restructure failed: missing block: B:45:0x00e0, code lost:
    
        r1 = null;
     */
    @Override // com.google.android.gms.internal.ads.JE
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.quizlet.data.interactor.folderwithcreator.m N(com.google.android.gms.internal.ads.HE r25, com.google.android.gms.internal.ads.C1832aG r26, float r27) {
        /*
            Method dump skipped, instructions count: 590
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2293l.N(com.google.android.gms.internal.ads.HE, com.google.android.gms.internal.ads.aG, float):com.quizlet.data.interactor.folderwithcreator.m");
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final ArrayList O(C1 c1, C1832aG c1832aG) {
        List listQ0 = q0(this.F1, c1, c1832aG, false, false);
        HashMap map = ME.a;
        ArrayList arrayList = new ArrayList(listQ0);
        Collections.sort(arrayList, new Cr(new UD(c1832aG), 1));
        return arrayList;
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void R(MC mc) {
        if (this.P1) {
            ByteBuffer byteBuffer = mc.h;
            byteBuffer.getClass();
            if (byteBuffer.remaining() >= 7) {
                byte b = byteBuffer.get();
                short s = byteBuffer.getShort();
                short s3 = byteBuffer.getShort();
                byte b2 = byteBuffer.get();
                byte b3 = byteBuffer.get();
                byteBuffer.position(0);
                if (b == -75 && s == 60 && s3 == 1 && b2 == 4) {
                    if (b3 == 0 || b3 == 1) {
                        byte[] bArr = new byte[byteBuffer.remaining()];
                        byteBuffer.get(bArr);
                        byteBuffer.position(0);
                        GE ge = this.I;
                        ge.getClass();
                        Bundle bundle = new Bundle();
                        bundle.putByteArray("hdr10-plus-info", bArr);
                        ge.o(bundle);
                    }
                }
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void S(Exception exc) {
        AbstractC2096gb.A("MediaCodecVideoRenderer", "Video codec error", exc);
        Fi fi = this.H1;
        Handler handler = (Handler) fi.b;
        if (handler != null) {
            handler.post(new A(fi, exc, 2));
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void T(long j, long j2, String str) {
        String str2;
        MediaCodecInfo.CodecProfileLevel[] codecProfileLevelArr;
        Fi fi = this.H1;
        Handler handler = (Handler) fi.b;
        if (handler != null) {
            str2 = str;
            handler.post(new A(fi, str2, j, j2));
        } else {
            str2 = str;
        }
        this.O1 = o0(str2);
        HE he = this.X;
        he.getClass();
        boolean z = false;
        if (Build.VERSION.SDK_INT >= 29 && "video/x-vnd.on2.vp9".equals(he.b)) {
            MediaCodecInfo.CodecCapabilities codecCapabilities = he.d;
            if (codecCapabilities == null || (codecProfileLevelArr = codecCapabilities.profileLevels) == null) {
                codecProfileLevelArr = new MediaCodecInfo.CodecProfileLevel[0];
            }
            int length = codecProfileLevelArr.length;
            int i = 0;
            while (true) {
                if (i >= length) {
                    break;
                }
                if (codecProfileLevelArr[i].profile == 16384) {
                    z = true;
                    break;
                }
                i++;
            }
        }
        this.P1 = z;
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void U(String str) {
        Fi fi = this.H1;
        Handler handler = (Handler) fi.b;
        if (handler != null) {
            handler.post(new A(fi, str, 4));
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void V(C1832aG c1832aG, MediaFormat mediaFormat) {
        GE ge = this.I;
        if (ge != null) {
            ge.j(this.Y1);
        }
        mediaFormat.getClass();
        boolean z = mediaFormat.containsKey("crop-right") && mediaFormat.containsKey("crop-left") && mediaFormat.containsKey("crop-bottom") && mediaFormat.containsKey("crop-top");
        int integer = z ? (mediaFormat.getInteger("crop-right") - mediaFormat.getInteger("crop-left")) + 1 : mediaFormat.getInteger(OTUXParamsKeys.OT_UX_WIDTH);
        int integer2 = z ? (mediaFormat.getInteger("crop-bottom") - mediaFormat.getInteger("crop-top")) + 1 : mediaFormat.getInteger(OTUXParamsKeys.OT_UX_HEIGHT);
        float f = c1832aG.x;
        int i = c1832aG.w;
        if (i == 90 || i == 270) {
            f = 1.0f / f;
            int i2 = integer2;
            integer2 = integer;
            integer = i2;
        }
        this.h2 = new C1740Nd(integer, f, integer2);
        E e = this.Q1;
        if (e == null || !this.o2) {
            this.J1.e(c1832aG.v);
        } else {
            EF ef = new EF(c1832aG);
            ef.s = integer;
            ef.t = integer2;
            ef.w = f;
            C1832aG c1832aG2 = new C1832aG(ef);
            int i3 = this.S1;
            List list = this.T1;
            if (list == null) {
                list = Bu.e;
            }
            e.P(c1832aG2, this.z1.b, i3, list);
            this.S1 = 2;
        }
        this.o2 = false;
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void W() {
        E e = this.Q1;
        if (e != null) {
            e.G();
            long j = this.m2;
            if (j == -9223372036854775807L) {
                j = this.z1.b;
                this.m2 = j;
            }
            this.Q1.V(-j);
        } else {
            this.J1.d(2);
        }
        this.o2 = true;
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void X() {
        E e = this.Q1;
        if (e != null) {
            e.G();
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final boolean Y(long j, long j2, GE ge, ByteBuffer byteBuffer, int i, int i2, int i3, long j3, boolean z, boolean z2, C1832aG c1832aG) {
        ge.getClass();
        long j4 = j3 - this.z1.c;
        int i4 = 0;
        while (true) {
            PriorityQueue priorityQueue = this.M1;
            Long l = (Long) priorityQueue.peek();
            if (l == null || l.longValue() >= j3) {
                break;
            }
            priorityQueue.poll();
            i4++;
        }
        l0(i4, 0);
        E e = this.Q1;
        if (e != null) {
            if (!z || z2) {
                return e.I(j3 + (-this.m2), new C2207j(this, ge, i, j4));
            }
            k0(ge, i);
            return true;
        }
        long j5 = this.z1.b;
        C2722v c2722v = this.J1;
        C2679u c2679u = this.K1;
        int iA = c2722v.a(j3, j, j2, j5, z, z2, c2679u);
        if (iA == 0) {
            this.g.getClass();
            long jNanoTime = System.nanoTime();
            InterfaceC2636t interfaceC2636t = this.l2;
            if (interfaceC2636t != null) {
                interfaceC2636t.a(j4, jNanoTime, c1832aG, this.K);
            }
            t0(ge, i, jNanoTime);
            m0(c2679u.a);
            return true;
        }
        if (iA == 1) {
            long j6 = c2679u.b;
            long j7 = c2679u.a;
            if (j6 == this.g2) {
                k0(ge, i);
            } else {
                InterfaceC2636t interfaceC2636t2 = this.l2;
                if (interfaceC2636t2 != null) {
                    interfaceC2636t2.a(j4, j6, c1832aG, this.K);
                }
                t0(ge, i, j6);
            }
            m0(j7);
            this.g2 = j6;
            return true;
        }
        if (iA != 2) {
            if (iA != 3) {
                return false;
            }
            k0(ge, i);
            m0(c2679u.a);
            return true;
        }
        Trace.beginSection("dropVideoBuffer");
        ge.m(i);
        Trace.endSection();
        l0(0, 1);
        m0(c2679u.a);
        return true;
    }

    @Override // com.google.android.gms.internal.ads.ID
    public final void c(int i, Object obj) throws Throwable {
        if (i == 1) {
            u0(obj);
            return;
        }
        if (i == 7) {
            obj.getClass();
            InterfaceC2636t interfaceC2636t = (InterfaceC2636t) obj;
            this.l2 = interfaceC2636t;
            E e = this.Q1;
            if (e != null) {
                e.O(interfaceC2636t);
                return;
            }
            return;
        }
        if (i == 10) {
            obj.getClass();
            int iIntValue = ((Integer) obj).intValue();
            if (this.k2 != iIntValue) {
                this.k2 = iIntValue;
                return;
            }
            return;
        }
        if (i == 4) {
            obj.getClass();
            int iIntValue2 = ((Integer) obj).intValue();
            this.Y1 = iIntValue2;
            GE ge = this.I;
            if (ge != null) {
                ge.j(iIntValue2);
                return;
            }
            return;
        }
        if (i == 5) {
            obj.getClass();
            int iIntValue3 = ((Integer) obj).intValue();
            this.Z1 = iIntValue3;
            E e2 = this.Q1;
            if (e2 != null) {
                e2.R(iIntValue3);
                return;
            }
            C2851y c2851y = this.J1.b;
            if (c2851y.j == iIntValue3) {
                return;
            }
            c2851y.j = iIntValue3;
            c2851y.d(true);
            return;
        }
        if (i == 13) {
            obj.getClass();
            List list = (List) obj;
            if (list.equals(InterfaceC1811Zc.a)) {
                E e3 = this.Q1;
                if (e3 == null || !e3.T()) {
                    return;
                }
                e3.l();
                return;
            }
            this.T1 = list;
            E e4 = this.Q1;
            if (e4 != null) {
                e4.W(list);
                return;
            }
            return;
        }
        if (i == 14) {
            obj.getClass();
            Pn pn = (Pn) obj;
            if (pn.a == 0 || pn.b == 0) {
                return;
            }
            this.W1 = pn;
            E e5 = this.Q1;
            if (e5 != null) {
                Surface surface = this.U1;
                AbstractC1795We.p(surface);
                e5.H(surface, pn);
                return;
            }
            return;
        }
        if (i == 16) {
            obj.getClass();
            this.j2 = ((Integer) obj).intValue();
            GE ge2 = this.I;
            if (ge2 == null || Build.VERSION.SDK_INT < 35) {
                return;
            }
            Bundle bundle = new Bundle();
            bundle.putInt("importance", Math.max(0, -this.j2));
            ge2.o(bundle);
            return;
        }
        if (i == 17) {
            Surface surface2 = this.U1;
            u0(null);
            obj.getClass();
            ((C2293l) obj).c(1, surface2);
            return;
        }
        if (i == 11) {
            C2307lD c2307lD = (C2307lD) obj;
            c2307lD.getClass();
            this.E = c2307lD;
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void d() {
        E e = this.Q1;
        if (e == null || !this.G1) {
            return;
        }
        e.m();
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.google.android.gms.internal.ads.JE
    public final void e() {
        try {
            try {
                L();
                w();
            } finally {
                this.E1 = null;
            }
        } finally {
            this.R1 = false;
            this.m2 = -9223372036854775807L;
            zzaax zzaaxVar = this.V1;
            if (zzaaxVar != null) {
                zzaaxVar.release();
                this.V1 = null;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void f() {
        this.b2 = 0;
        this.g.getClass();
        this.a2 = SystemClock.elapsedRealtime();
        this.e2 = 0L;
        this.f2 = 0;
        E e = this.Q1;
        if (e != null) {
            e.Q();
        } else {
            this.J1.b();
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void g() {
        int i = this.b2;
        Fi fi = this.H1;
        if (i > 0) {
            this.g.getClass();
            long jElapsedRealtime = SystemClock.elapsedRealtime();
            long j = jElapsedRealtime - this.a2;
            int i2 = this.b2;
            Handler handler = (Handler) fi.b;
            if (handler != null) {
                handler.post(new B(i2, 0, j, fi));
            }
            this.b2 = 0;
            this.a2 = jElapsedRealtime;
        }
        int i3 = this.f2;
        if (i3 != 0) {
            long j2 = this.e2;
            Handler handler2 = (Handler) fi.b;
            if (handler2 != null) {
                handler2.post(new A(fi, j2, i3));
            }
            this.e2 = 0L;
            this.f2 = 0;
        }
        E e = this.Q1;
        if (e != null) {
            e.B();
        } else {
            this.J1.c();
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void g0() {
        E e = this.Q1;
        if (e == null) {
            C2722v c2722v = this.J1;
            if (c2722v.d == 0) {
                c2722v.d = 1;
                return;
            }
            return;
        }
        int i = this.S1;
        if (i == 0 || i == 1) {
            this.S1 = 0;
        } else {
            e.g();
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void h(C1832aG[] c1832aGArr, long j, long j2, C2093gF c2093gF) {
        super.h(c1832aGArr, j, j2, c2093gF);
        A9 a9 = this.p;
        if (a9.o()) {
            this.n2 = -9223372036854775807L;
        } else {
            this.n2 = a9.n(c2093gF.a, new C2303l9()).d;
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void h0() {
        Fi fi = this.H1;
        this.i2 = null;
        this.n2 = -9223372036854775807L;
        this.X1 = false;
        try {
            super.h0();
            QC qc = this.y1;
            fi.getClass();
            synchronized (qc) {
            }
            Handler handler = (Handler) fi.b;
            if (handler != null) {
                handler.post(new Qv(2, fi, qc));
            }
            fi.D(C1740Nd.d);
        } catch (Throwable th) {
            QC qc2 = this.y1;
            fi.getClass();
            synchronized (qc2) {
                Handler handler2 = (Handler) fi.b;
                if (handler2 != null) {
                    handler2.post(new Qv(2, fi, qc2));
                }
                fi.D(C1740Nd.d);
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void i0(boolean z, boolean z2) {
        E e;
        int i = 1;
        this.y1 = new QC();
        e0();
        QC qc = this.y1;
        Fi fi = this.H1;
        Handler handler = (Handler) fi.b;
        if (handler != null) {
            handler.post(new A(fi, qc, 3));
        }
        boolean z3 = this.R1;
        C2722v c2722v = this.J1;
        if (!z3) {
            if (this.T1 != null && this.Q1 == null) {
                Context context = this.F1;
                com.amazon.aps.ads.privacy.a aVar = new com.amazon.aps.ads.privacy.a();
                aVar.c = context.getApplicationContext();
                aVar.d = c2722v;
                C2244ju c2244ju = AbstractC2330lu.b;
                aVar.g = Bu.e;
                aVar.h = C1.h;
                aVar.i = C1847ao.a;
                aVar.a = true;
                C1847ao c1847ao = this.g;
                c1847ao.getClass();
                aVar.i = c1847ao;
                AbstractC1795We.L(!aVar.b);
                if (((C2508q) aVar.f) == null) {
                    if (((C2465p) aVar.e) == null) {
                        aVar.e = new C2465p();
                    }
                    aVar.f = new C2508q((C2465p) aVar.e);
                }
                C2593s c2593s = new C2593s(aVar);
                aVar.b = true;
                c2593s.n = 1;
                SparseArray sparseArray = c2593s.c;
                if (sparseArray.indexOfKey(0) >= 0) {
                    e = (E) sparseArray.get(0);
                } else {
                    C2422o c2422o = new C2422o(c2593s, c2593s.a);
                    c2593s.g.add(c2422o);
                    sparseArray.put(0, c2422o);
                    e = c2422o;
                }
                this.Q1 = e;
            }
            this.R1 = true;
        }
        int i2 = !z2 ? 1 : 0;
        E e2 = this.Q1;
        if (e2 == null) {
            C1847ao c1847ao2 = this.g;
            c1847ao2.getClass();
            c2722v.k = c1847ao2;
            c2722v.d(i2);
            return;
        }
        e2.S(new Ts(this, i));
        InterfaceC2636t interfaceC2636t = this.l2;
        if (interfaceC2636t != null) {
            this.Q1.O(interfaceC2636t);
        }
        if (this.U1 != null && !this.W1.equals(Pn.c)) {
            this.Q1.H(this.U1, this.W1);
        }
        this.Q1.R(this.Z1);
        this.Q1.M(this.G);
        List list = this.T1;
        if (list != null) {
            this.Q1.W(list);
        }
        this.S1 = i2;
        this.C1 = true;
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void j0(long j, boolean z) {
        E e = this.Q1;
        if (e != null && !z) {
            e.E(true);
        }
        super.j0(j, z);
        E e2 = this.Q1;
        C2722v c2722v = this.J1;
        if (e2 == null) {
            C2851y c2851y = c2722v.b;
            c2851y.m = 0L;
            c2851y.p = -1L;
            c2851y.n = -1L;
            c2722v.g = -9223372036854775807L;
            c2722v.e = -9223372036854775807L;
            c2722v.d = Math.min(c2722v.d, 1);
            c2722v.h = -9223372036854775807L;
        }
        if (z) {
            E e3 = this.Q1;
            if (e3 != null) {
                e3.N(false);
            } else {
                c2722v.i = false;
                c2722v.h = -9223372036854775807L;
            }
        }
        this.c2 = 0;
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void k(float f, float f2) {
        super.k(f, f2);
        E e = this.Q1;
        if (e != null) {
            e.M(f);
        } else {
            this.J1.g(f);
        }
    }

    public final void k0(GE ge, int i) {
        Trace.beginSection("skipVideoBuffer");
        ge.m(i);
        Trace.endSection();
        this.y1.f++;
    }

    public final void l0(int i, int i2) {
        QC qc = this.y1;
        qc.h += i;
        int i3 = i + i2;
        qc.g += i3;
        this.b2 += i3;
        int i4 = this.c2 + i3;
        this.c2 = i4;
        qc.i = Math.max(i4, qc.i);
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final String m() {
        return "MediaCodecVideoRenderer";
    }

    public final void m0(long j) {
        QC qc = this.y1;
        qc.k += j;
        qc.l++;
        this.e2 += j;
        this.f2++;
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void n(long j, long j2) throws Throwable {
        E e = this.Q1;
        if (e != null) {
            try {
                e.J(j, j2);
            } catch (zzacg e2) {
                throw b0(e2, e2.a, false, 7001);
            }
        }
        super.n(j, j2);
    }

    public final boolean n0(long j, long j2, boolean z, boolean z2) throws Throwable {
        long j3 = this.L1;
        if (j3 != -9223372036854775807L) {
            this.p2 = j2 > this.l + 200000 && j < j3;
        }
        if (j < -500000 && !z) {
            AF af = this.i;
            af.getClass();
            int iA = af.a(j2 - this.k);
            if (iA != 0) {
                PriorityQueue priorityQueue = this.M1;
                if (z2) {
                    QC qc = this.y1;
                    int i = qc.d + iA;
                    qc.d = i;
                    qc.f += this.d2;
                    qc.d = priorityQueue.size() + i;
                } else {
                    this.y1.j++;
                    l0(priorityQueue.size() + iA, this.d2);
                }
                if (z()) {
                    t();
                }
                E e = this.Q1;
                if (e != null) {
                    e.E(false);
                }
                return true;
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final boolean o() {
        if (!this.w1) {
            return false;
        }
        E e = this.Q1;
        return e == null || e.K();
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final boolean p() {
        boolean zP = super.p();
        E e = this.Q1;
        if (e != null) {
            return e.U(zP);
        }
        if (zP && this.I == null) {
            return true;
        }
        return this.J1.h(zP);
    }

    /* JADX WARN: Removed duplicated region for block: B:44:0x006c  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x006f  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x0086 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.view.Surface p0(com.google.android.gms.internal.ads.HE r7) {
        /*
            Method dump skipped, instructions count: 196
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2293l.p0(com.google.android.gms.internal.ads.HE):android.view.Surface");
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final float r(float f, C1832aG[] c1832aGArr) {
        float fMax = -1.0f;
        for (C1832aG c1832aG : c1832aGArr) {
            float f2 = c1832aG.v;
            if (f2 != -1.0f) {
                fMax = Math.max(fMax, f2);
            }
        }
        if (fMax == -1.0f) {
            return -1.0f;
        }
        return fMax * f;
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final zztb s(IllegalStateException illegalStateException, HE he) {
        Surface surface = this.U1;
        zzaao zzaaoVar = new zzaao(illegalStateException, he);
        System.identityHashCode(surface);
        if (surface != null) {
            surface.isValid();
        }
        return zzaaoVar;
    }

    public final void t0(GE ge, int i, long j) {
        Surface surface;
        Trace.beginSection("releaseOutputBuffer");
        ge.h(i, j);
        Trace.endSection();
        this.y1.e++;
        this.c2 = 0;
        if (this.Q1 == null) {
            C1740Nd c1740Nd = this.h2;
            boolean zEquals = c1740Nd.equals(C1740Nd.d);
            Fi fi = this.H1;
            if (!zEquals && !c1740Nd.equals(this.i2)) {
                this.i2 = c1740Nd;
                fi.D(c1740Nd);
            }
            C2722v c2722v = this.J1;
            int i2 = c2722v.d;
            c2722v.d = 3;
            c2722v.k.getClass();
            c2722v.f = Yo.t(SystemClock.elapsedRealtime());
            if (i2 == 3 || (surface = this.U1) == null) {
                return;
            }
            Handler handler = (Handler) fi.b;
            if (handler != null) {
                handler.post(new com.android.volley.i(fi, surface, SystemClock.elapsedRealtime(), 1, false));
            }
            this.X1 = true;
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void u(long j) {
        super.u(j);
        this.d2--;
    }

    public final void u0(Object obj) throws Throwable {
        Handler handler;
        Surface surface = obj instanceof Surface ? (Surface) obj : null;
        Surface surface2 = this.U1;
        Fi fi = this.H1;
        if (surface2 == surface) {
            if (surface != null) {
                C1740Nd c1740Nd = this.i2;
                if (c1740Nd != null) {
                    fi.D(c1740Nd);
                }
                Surface surface3 = this.U1;
                if (surface3 == null || !this.X1 || (handler = (Handler) fi.b) == null) {
                    return;
                }
                handler.post(new com.android.volley.i(fi, surface3, SystemClock.elapsedRealtime(), 1, false));
                return;
            }
            return;
        }
        this.U1 = surface;
        E e = this.Q1;
        C2722v c2722v = this.J1;
        if (e == null) {
            c2722v.f(surface);
        }
        this.X1 = false;
        int i = this.h;
        GE ge = this.I;
        if (ge != null && this.Q1 == null) {
            HE he = this.X;
            he.getClass();
            if (!v0(he) || this.O1) {
                w();
                t();
            } else {
                Surface surfaceP0 = p0(he);
                if (surfaceP0 != null) {
                    ge.f(surfaceP0);
                } else {
                    if (Build.VERSION.SDK_INT < 35) {
                        throw new IllegalStateException();
                    }
                    ge.zzi();
                }
            }
        }
        if (surface != null) {
            C1740Nd c1740Nd2 = this.i2;
            if (c1740Nd2 != null) {
                fi.D(c1740Nd2);
            }
        } else {
            this.i2 = null;
            E e2 = this.Q1;
            if (e2 != null) {
                e2.zzi();
            }
        }
        if (i == 2) {
            E e3 = this.Q1;
            if (e3 != null) {
                e3.N(true);
            } else {
                c2722v.i = true;
                c2722v.h = -9223372036854775807L;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void v() {
        this.d2++;
    }

    public final boolean v0(HE he) {
        if (this.Q1 != null) {
            return true;
        }
        Surface surface = this.U1;
        if (surface != null && surface.isValid()) {
            return true;
        }
        if (Build.VERSION.SDK_INT >= 35 && he.h) {
            return true;
        }
        if (o0(he.a)) {
            return false;
        }
        return !he.f || zzaax.a();
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void x() {
        super.x();
        this.M1.clear();
        this.p2 = false;
        this.d2 = 0;
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final boolean z() {
        HE he = this.X;
        if (this.Q1 != null && he != null) {
            String str = he.a;
            if (str.equals("c2.mtk.avc.decoder") || str.equals("c2.mtk.hevc.decoder")) {
                w();
                return true;
            }
        }
        return super.z();
    }
}
