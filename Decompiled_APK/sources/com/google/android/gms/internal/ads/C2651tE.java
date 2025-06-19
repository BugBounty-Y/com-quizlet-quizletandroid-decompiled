package com.google.android.gms.internal.ads;

import android.content.Context;
import android.media.AudioDeviceInfo;
import android.media.AudioTrack;
import android.media.LoudnessCodecController;
import android.media.MediaCodec;
import android.media.MediaFormat;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Pair;
import androidx.core.app.NotificationManagerCompat;
import com.facebook.internal.C1549d;
import java.math.RoundingMode;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.tE, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2651tE extends JE implements InterfaceC2650tD {
    public final Fp F1;
    public final C2608sE G1;
    public final Fp H1;
    public int I1;
    public boolean J1;
    public C1832aG K1;
    public C1832aG L1;
    public long M1;
    public boolean N1;
    public boolean O1;
    public boolean P1;
    public int Q1;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C2651tE(Context context, Wr wr, Handler handler, SurfaceHolderCallbackC2091gD surfaceHolderCallbackC2091gD, C2608sE c2608sE) {
        super(1, wr, 44100.0f);
        Fp fp = Build.VERSION.SDK_INT >= 35 ? new Fp(12) : null;
        context.getApplicationContext();
        this.G1 = c2608sE;
        this.H1 = fp;
        this.Q1 = NotificationManagerCompat.IMPORTANCE_UNSPECIFIED;
        this.F1 = new Fp(handler, false, surfaceHolderCallbackC2091gD, 11);
        c2608sE.l = new Sq(this);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:19:0x003f  */
    @Override // com.google.android.gms.internal.ads.JE
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int I(com.google.android.gms.internal.ads.C1 r18, com.google.android.gms.internal.ads.C1832aG r19) {
        /*
            Method dump skipped, instructions count: 502
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2651tE.I(com.google.android.gms.internal.ads.C1, com.google.android.gms.internal.ads.aG):int");
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final RC J(HE he, C1832aG c1832aG, C1832aG c1832aG2) {
        int i;
        int i2;
        RC rcA = he.a(c1832aG, c1832aG2);
        boolean z = this.E1 == null && Z(c1832aG2);
        int i3 = rcA.e;
        if (z) {
            i3 |= 32768;
        }
        "OMX.google.raw.decoder".equals(he.a);
        if (c1832aG2.n > this.I1) {
            i3 |= 64;
        }
        if (i3 != 0) {
            i = 0;
            i2 = i3;
        } else {
            i = rcA.d;
            i2 = 0;
        }
        return new RC(he.a, c1832aG, c1832aG2, i, i2);
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final RC K(Ps ps) throws Throwable {
        C1832aG c1832aG = (C1832aG) ps.a;
        c1832aG.getClass();
        this.K1 = c1832aG;
        RC rcK = super.K(ps);
        Fp fp = this.F1;
        Handler handler = (Handler) fp.b;
        if (handler != null) {
            handler.post(new C(fp, c1832aG, rcK, 12));
        }
        return rcK;
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final com.quizlet.data.interactor.folderwithcreator.m N(HE he, C1832aG c1832aG, float f) {
        C1832aG[] c1832aGArr = this.j;
        c1832aGArr.getClass();
        int length = c1832aGArr.length;
        String str = he.a;
        "OMX.google.raw.decoder".equals(str);
        int iMax = c1832aG.n;
        if (length != 1) {
            for (C1832aG c1832aG2 : c1832aGArr) {
                if (he.a(c1832aG, c1832aG2).d != 0) {
                    "OMX.google.raw.decoder".equals(str);
                    iMax = Math.max(iMax, c1832aG2.n);
                }
            }
        }
        this.I1 = iMax;
        int i = Build.VERSION.SDK_INT;
        this.J1 = str.equals("OMX.google.opus.decoder") || str.equals("c2.android.opus.decoder") || str.equals("OMX.google.vorbis.decoder") || str.equals("c2.android.vorbis.decoder");
        int i2 = this.I1;
        MediaFormat mediaFormat = new MediaFormat();
        mediaFormat.setString("mime", he.c);
        int i3 = c1832aG.C;
        mediaFormat.setInteger("channel-count", i3);
        int i4 = c1832aG.D;
        mediaFormat.setInteger("sample-rate", i4);
        AbstractC1972di.p(mediaFormat, c1832aG.p);
        AbstractC1972di.e(mediaFormat, "max-input-size", i2);
        mediaFormat.setInteger("priority", 0);
        if (f != -1.0f) {
            mediaFormat.setFloat("operating-rate", f);
        }
        String str2 = c1832aG.m;
        if ("audio/ac4".equals(str2)) {
            Pair pairA = Hi.a(c1832aG);
            if (pairA != null) {
                AbstractC1972di.e(mediaFormat, "profile", ((Integer) pairA.first).intValue());
                AbstractC1972di.e(mediaFormat, "level", ((Integer) pairA.second).intValue());
            }
            if (i <= 28) {
                mediaFormat.setInteger("ac4-is-sync", 1);
            }
        }
        EF ef = new EF();
        ef.d("audio/raw");
        ef.B = i3;
        ef.C = i4;
        ef.D = 4;
        if (this.G1.l(new C1832aG(ef)) == 2) {
            mediaFormat.setInteger("pcm-encoding", 4);
        }
        if (i >= 32) {
            mediaFormat.setInteger("max-output-channel-count", 99);
        }
        if (i >= 35) {
            mediaFormat.setInteger("importance", Math.max(0, -this.Q1));
        }
        C1832aG c1832aG3 = null;
        if ("audio/raw".equals(he.b) && !"audio/raw".equals(str2)) {
            c1832aG3 = c1832aG;
        }
        this.L1 = c1832aG3;
        return new com.quizlet.data.interactor.folderwithcreator.m(he, mediaFormat, c1832aG, (Object) null, this.H1);
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x002b  */
    @Override // com.google.android.gms.internal.ads.JE
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.util.ArrayList O(com.google.android.gms.internal.ads.C1 r4, com.google.android.gms.internal.ads.C1832aG r5) {
        /*
            r3 = this;
            java.lang.String r0 = r5.m
            if (r0 != 0) goto L7
            com.google.android.gms.internal.ads.Bu r4 = com.google.android.gms.internal.ads.Bu.e
            goto L2f
        L7:
            com.google.android.gms.internal.ads.sE r0 = r3.G1
            int r0 = r0.l(r5)
            r1 = 0
            if (r0 == 0) goto L2b
            java.lang.String r0 = "audio/raw"
            java.util.List r0 = com.google.android.gms.internal.ads.ME.b(r0, r1, r1)
            boolean r2 = r0.isEmpty()
            if (r2 == 0) goto L1e
            r0 = 0
            goto L24
        L1e:
            java.lang.Object r0 = r0.get(r1)
            com.google.android.gms.internal.ads.HE r0 = (com.google.android.gms.internal.ads.HE) r0
        L24:
            if (r0 == 0) goto L2b
            com.google.android.gms.internal.ads.Bu r4 = com.google.android.gms.internal.ads.AbstractC2330lu.s(r0)
            goto L2f
        L2b:
            com.google.android.gms.internal.ads.Bu r4 = com.google.android.gms.internal.ads.ME.c(r4, r5, r1, r1)
        L2f:
            java.util.HashMap r0 = com.google.android.gms.internal.ads.ME.a
            java.util.ArrayList r0 = new java.util.ArrayList
            r0.<init>(r4)
            com.google.android.gms.internal.ads.UD r4 = new com.google.android.gms.internal.ads.UD
            r4.<init>(r5)
            com.google.android.gms.internal.ads.Cr r5 = new com.google.android.gms.internal.ads.Cr
            r1 = 1
            r5.<init>(r4, r1)
            java.util.Collections.sort(r0, r5)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2651tE.O(com.google.android.gms.internal.ads.C1, com.google.android.gms.internal.ads.aG):java.util.ArrayList");
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void R(MC mc) {
        C1832aG c1832aG;
        if (Build.VERSION.SDK_INT < 29 || (c1832aG = mc.c) == null || !Objects.equals(c1832aG.m, "audio/opus") || !this.j1) {
            return;
        }
        ByteBuffer byteBuffer = mc.h;
        byteBuffer.getClass();
        mc.c.getClass();
        if (byteBuffer.remaining() == 8) {
            byteBuffer.order(ByteOrder.LITTLE_ENDIAN).getLong();
            AudioTrack audioTrack = this.G1.p;
            if (audioTrack != null) {
                C2608sE.m(audioTrack);
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void S(Exception exc) {
        AbstractC2096gb.A("MediaCodecAudioRenderer", "Audio codec error", exc);
        Fp fp = this.F1;
        Handler handler = (Handler) fp.b;
        if (handler != null) {
            handler.post(new RunnableC2180iE(fp, exc, 5));
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void T(long j, long j2, String str) {
        Fp fp = this.F1;
        Handler handler = (Handler) fp.b;
        if (handler != null) {
            handler.post(new RunnableC2180iE(fp, str, j, j2));
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void U(String str) {
        Fp fp = this.F1;
        Handler handler = (Handler) fp.b;
        if (handler != null) {
            handler.post(new RunnableC2180iE(fp, str, 8));
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void V(C1832aG c1832aG, MediaFormat mediaFormat) throws zzik {
        C1832aG c1832aG2 = this.L1;
        int[] iArr = null;
        boolean z = true;
        if (c1832aG2 != null) {
            c1832aG = c1832aG2;
        } else if (this.I != null) {
            mediaFormat.getClass();
            int integer = "audio/raw".equals(c1832aG.m) ? c1832aG.E : mediaFormat.containsKey("pcm-encoding") ? mediaFormat.getInteger("pcm-encoding") : mediaFormat.containsKey("v-bits-per-sample") ? Yo.r(mediaFormat.getInteger("v-bits-per-sample")) : 2;
            EF ef = new EF();
            ef.d("audio/raw");
            ef.D = integer;
            ef.E = c1832aG.F;
            ef.F = c1832aG.G;
            ef.j = c1832aG.k;
            ef.a = c1832aG.a;
            ef.b = c1832aG.b;
            ef.c = AbstractC2330lu.n(c1832aG.c);
            ef.d = c1832aG.d;
            ef.e = c1832aG.e;
            ef.f = c1832aG.f;
            ef.B = mediaFormat.getInteger("channel-count");
            ef.C = mediaFormat.getInteger("sample-rate");
            c1832aG = new C1832aG(ef);
            if (this.J1) {
                int i = c1832aG.C;
                if (i == 3) {
                    iArr = new int[]{0, 2, 1};
                } else if (i == 5) {
                    iArr = new int[]{0, 2, 1, 3, 4};
                } else if (i == 6) {
                    iArr = new int[]{0, 2, 1, 5, 3, 4};
                } else if (i == 7) {
                    iArr = new int[]{0, 2, 1, 6, 5, 3, 4};
                } else if (i == 8) {
                    iArr = new int[]{0, 2, 1, 7, 5, 6, 3, 4};
                }
            }
        }
        try {
            int i2 = Build.VERSION.SDK_INT;
            if (i2 >= 29) {
                if (this.j1) {
                    e0();
                }
                if (i2 < 29) {
                    z = false;
                }
                AbstractC1795We.L(z);
            }
            this.G1.o(c1832aG, iArr);
        } catch (zzqd e) {
            throw b0(e, e.a, false, com.pubmatic.sdk.common.h.INVALID_REWARD_SELECTED);
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void W() {
        this.G1.D = true;
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void X() throws IllegalStateException, zzik {
        try {
            C2608sE c2608sE = this.G1;
            if (!c2608sE.K && c2608sE.k() && c2608sE.j()) {
                c2608sE.g();
                c2608sE.K = true;
            }
        } catch (zzqh e) {
            throw b0(e, e.c, e.b, true != this.j1 ? com.pubmatic.sdk.common.h.REWARD_NOT_SELECTED : 5003);
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final boolean Y(long j, long j2, GE ge, ByteBuffer byteBuffer, int i, int i2, int i3, long j3, boolean z, boolean z2, C1832aG c1832aG) throws zzik {
        byteBuffer.getClass();
        if (this.L1 != null && (i2 & 2) != 0) {
            ge.getClass();
            ge.m(i);
            return true;
        }
        C2608sE c2608sE = this.G1;
        if (z) {
            if (ge != null) {
                ge.m(i);
            }
            this.y1.f += i3;
            c2608sE.D = true;
            return true;
        }
        try {
            if (!c2608sE.s(byteBuffer, j3, i3)) {
                return false;
            }
            if (ge != null) {
                ge.m(i);
            }
            this.y1.e += i3;
            return true;
        } catch (zzqe e) {
            C1832aG c1832aG2 = this.K1;
            if (this.j1) {
                e0();
            }
            throw b0(e, c1832aG2, e.b, com.pubmatic.sdk.common.h.INVALID_REWARD_SELECTED);
        } catch (zzqh e2) {
            if (this.j1) {
                e0();
            }
            throw b0(e2, c1832aG, e2.b, com.pubmatic.sdk.common.h.REWARD_NOT_SELECTED);
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final boolean Z(C1832aG c1832aG) {
        e0();
        return this.G1.l(c1832aG) != 0;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2650tD
    public final C2040f6 a() {
        return this.G1.w;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2650tD
    public final void b(C2040f6 c2040f6) {
        C2608sE c2608sE = this.G1;
        c2608sE.getClass();
        float f = c2040f6.a;
        String str = Yo.a;
        c2608sE.w = new C2040f6(Math.max(0.1f, Math.min(f, 8.0f)), Math.max(0.1f, Math.min(c2040f6.b, 8.0f)));
        C2480pE c2480pE = new C2480pE(c2040f6, -9223372036854775807L, -9223372036854775807L);
        if (c2608sE.k()) {
            c2608sE.u = c2480pE;
        } else {
            c2608sE.v = c2480pE;
        }
    }

    @Override // com.google.android.gms.internal.ads.ID
    public final void c(int i, Object obj) throws IllegalStateException {
        C2883yp c2883yp;
        Fp fp;
        C2608sE c2608sE = this.G1;
        if (i == 2) {
            obj.getClass();
            float fFloatValue = ((Float) obj).floatValue();
            if (c2608sE.G != fFloatValue) {
                c2608sE.G = fFloatValue;
                if (c2608sE.k()) {
                    c2608sE.p.setVolume(c2608sE.G);
                    return;
                }
                return;
            }
            return;
        }
        if (i == 3) {
            Wl wl = (Wl) obj;
            wl.getClass();
            if (c2608sE.t.equals(wl)) {
                return;
            }
            c2608sE.t = wl;
            Tm tm = c2608sE.r;
            if (tm != null) {
                tm.i = wl;
                tm.b(C2004eE.b((Context) tm.b, wl, (C2883yp) tm.h));
            }
            c2608sE.p();
            return;
        }
        if (i == 6) {
            Lp lp = (Lp) obj;
            lp.getClass();
            if (c2608sE.P.equals(lp)) {
                return;
            }
            if (c2608sE.p != null) {
                c2608sE.P.getClass();
            }
            c2608sE.P = lp;
            return;
        }
        if (i == 12) {
            AudioDeviceInfo audioDeviceInfo = (AudioDeviceInfo) obj;
            if (audioDeviceInfo == null) {
                c2883yp = null;
            } else {
                c2608sE.getClass();
                c2883yp = new C2883yp(audioDeviceInfo, 11);
            }
            c2608sE.Q = c2883yp;
            Tm tm2 = c2608sE.r;
            if (tm2 != null) {
                tm2.a(audioDeviceInfo);
            }
            AudioTrack audioTrack = c2608sE.p;
            if (audioTrack != null) {
                C2883yp c2883yp2 = c2608sE.Q;
                audioTrack.setPreferredDevice(c2883yp2 != null ? (AudioDeviceInfo) c2883yp2.b : null);
                return;
            }
            return;
        }
        if (i == 16) {
            obj.getClass();
            this.Q1 = ((Integer) obj).intValue();
            GE ge = this.I;
            if (ge == null || Build.VERSION.SDK_INT < 35) {
                return;
            }
            Bundle bundle = new Bundle();
            bundle.putInt("importance", Math.max(0, -this.Q1));
            ge.o(bundle);
            return;
        }
        if (i == 9) {
            obj.getClass();
            c2608sE.x = ((Boolean) obj).booleanValue();
            C2480pE c2480pE = new C2480pE(c2608sE.w, -9223372036854775807L, -9223372036854775807L);
            if (c2608sE.k()) {
                c2608sE.u = c2480pE;
                return;
            } else {
                c2608sE.v = c2480pE;
                return;
            }
        }
        if (i != 10) {
            if (i == 11) {
                C2307lD c2307lD = (C2307lD) obj;
                c2307lD.getClass();
                this.E = c2307lD;
                return;
            }
            return;
        }
        obj.getClass();
        int iIntValue = ((Integer) obj).intValue();
        if (c2608sE.O != iIntValue) {
            c2608sE.O = iIntValue;
            c2608sE.p();
        }
        if (Build.VERSION.SDK_INT < 35 || (fp = this.H1) == null) {
            return;
        }
        LoudnessCodecController loudnessCodecController = (LoudnessCodecController) fp.c;
        if (loudnessCodecController != null) {
            loudnessCodecController.close();
            fp.c = null;
        }
        LoudnessCodecController loudnessCodecControllerCreate = LoudnessCodecController.create(iIntValue, Kv.a, new FE());
        fp.c = loudnessCodecControllerCreate;
        Iterator it2 = ((HashSet) fp.b).iterator();
        while (it2.hasNext()) {
            if (!loudnessCodecControllerCreate.addMediaCodec((MediaCodec) it2.next())) {
                it2.remove();
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void d() {
        Fp fp;
        Tm tm = this.G1.r;
        if (tm != null && tm.a) {
            tm.g = null;
            Context context = (Context) tm.b;
            C2048fE c2048fE = (C2048fE) tm.d;
            if (c2048fE != null) {
                AbstractC1795We.s(context).unregisterAudioDeviceCallback(c2048fE);
            }
            context.unregisterReceiver((C1549d) tm.e);
            C2092gE c2092gE = (C2092gE) tm.f;
            if (c2092gE != null) {
                c2092gE.a.unregisterContentObserver(c2092gE);
            }
            tm.a = false;
        }
        if (Build.VERSION.SDK_INT < 35 || (fp = this.H1) == null) {
            return;
        }
        ((HashSet) fp.b).clear();
        LoudnessCodecController loudnessCodecController = (LoudnessCodecController) fp.c;
        if (loudnessCodecController != null) {
            loudnessCodecController.close();
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final InterfaceC2650tD d0() {
        return this;
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void e() throws IllegalStateException {
        C2608sE c2608sE = this.G1;
        this.P1 = false;
        try {
            try {
                L();
                w();
                if (this.O1) {
                    this.O1 = false;
                    c2608sE.r();
                }
            } finally {
                this.E1 = null;
            }
        } catch (Throwable th) {
            if (this.O1) {
                this.O1 = false;
                c2608sE.r();
            }
            throw th;
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void f() throws IllegalStateException {
        this.G1.q();
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void g() throws IllegalStateException {
        k0();
        C2608sE c2608sE = this.G1;
        c2608sE.N = false;
        if (c2608sE.k()) {
            C2265kE c2265kE = c2608sE.f;
            c2265kE.j = 0L;
            c2265kE.u = 0;
            c2265kE.t = 0;
            c2265kE.k = 0L;
            c2265kE.A = 0L;
            c2265kE.D = 0L;
            c2265kE.i = false;
            if (c2265kE.v == -9223372036854775807L) {
                C2222jE c2222jE = c2265kE.e;
                c2222jE.getClass();
                c2222jE.a(0);
            } else {
                c2265kE.x = c2265kE.c();
                if (!C2608sE.m(c2608sE.p)) {
                    return;
                }
            }
            c2608sE.p.pause();
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void h0() {
        Fp fp = this.F1;
        this.O1 = true;
        this.K1 = null;
        try {
            try {
                this.G1.p();
                super.h0();
                QC qc = this.y1;
                fp.getClass();
                synchronized (qc) {
                }
                Handler handler = (Handler) fp.b;
                if (handler != null) {
                    handler.post(new RunnableC2793wl(23, fp, qc));
                }
            } catch (Throwable th) {
                super.h0();
                QC qc2 = this.y1;
                fp.getClass();
                synchronized (qc2) {
                    Handler handler2 = (Handler) fp.b;
                    if (handler2 != null) {
                        handler2.post(new RunnableC2793wl(23, fp, qc2));
                    }
                    throw th;
                }
            }
        } catch (Throwable th2) {
            QC qc3 = this.y1;
            fp.getClass();
            synchronized (qc3) {
                Handler handler3 = (Handler) fp.b;
                if (handler3 != null) {
                    handler3.post(new RunnableC2793wl(23, fp, qc3));
                }
                throw th2;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2650tD
    public final boolean i() {
        boolean z = this.P1;
        this.P1 = false;
        return z;
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void i0(boolean z, boolean z2) {
        QC qc = new QC();
        this.y1 = qc;
        Fp fp = this.F1;
        Handler handler = (Handler) fp.b;
        if (handler != null) {
            handler.post(new RunnableC2180iE(fp, qc, 0));
        }
        e0();
        C1917cE c1917cE = this.f;
        c1917cE.getClass();
        C2608sE c2608sE = this.G1;
        c2608sE.k = c1917cE;
        C1847ao c1847ao = this.g;
        c1847ao.getClass();
        c2608sE.f.E = c1847ao;
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final void j0(long j, boolean z) throws IllegalStateException {
        super.j0(j, z);
        this.G1.p();
        this.M1 = j;
        this.P1 = false;
        this.N1 = true;
    }

    public final void k0() {
        long jMax;
        ArrayDeque arrayDeque;
        long j;
        o();
        C2608sE c2608sE = this.G1;
        if (!c2608sE.k() || c2608sE.E) {
            jMax = Long.MIN_VALUE;
        } else {
            long jMin = Math.min(c2608sE.f.a(), Yo.u(c2608sE.n.e, c2608sE.b()));
            while (true) {
                arrayDeque = c2608sE.g;
                if (arrayDeque.isEmpty() || jMin < ((C2480pE) arrayDeque.getFirst()).c) {
                    break;
                } else {
                    c2608sE.v = (C2480pE) arrayDeque.remove();
                }
            }
            C2480pE c2480pE = c2608sE.v;
            long jV = jMin - c2480pE.c;
            long jS = Yo.s(jV, c2480pE.a.a);
            boolean zIsEmpty = arrayDeque.isEmpty();
            Iw iw = c2608sE.X;
            if (zIsEmpty) {
                C1926cg c1926cg = (C1926cg) iw.b;
                if (c1926cg.h()) {
                    long j2 = c1926cg.o;
                    if (j2 >= 1024) {
                        long j3 = c1926cg.n;
                        C1808Yf c1808Yf = c1926cg.j;
                        c1808Yf.getClass();
                        int i = c1808Yf.k * c1808Yf.b;
                        long j4 = j3 - (i + i);
                        int i2 = c1926cg.h.a;
                        int i3 = c1926cg.g.a;
                        jV = i2 == i3 ? Yo.v(jV, j4, j2, RoundingMode.DOWN) : Yo.v(jV, j4 * i2, j2 * i3, RoundingMode.DOWN);
                    } else {
                        jV = (long) (c1926cg.c * jV);
                    }
                }
                C2480pE c2480pE2 = c2608sE.v;
                j = c2480pE2.b + jV;
                c2480pE2.d = jV - jS;
            } else {
                C2480pE c2480pE3 = c2608sE.v;
                j = c2480pE3.b + jS + c2480pE3.d;
            }
            long j5 = ((C2694uE) iw.a).l;
            jMax = Yo.u(c2608sE.n.e, j5) + j;
            long j6 = c2608sE.U;
            if (j5 > j6) {
                long jU = Yo.u(c2608sE.n.e, j5 - j6);
                c2608sE.U = j5;
                c2608sE.V += jU;
                if (c2608sE.W == null) {
                    c2608sE.W = new Handler(Looper.myLooper());
                }
                c2608sE.W.removeCallbacksAndMessages(null);
                c2608sE.W.postDelayed(new RunnableC2104gj(c2608sE, 26), 100L);
            }
        }
        if (jMax != Long.MIN_VALUE) {
            if (!this.N1) {
                jMax = Math.max(this.M1, jMax);
            }
            this.M1 = jMax;
            this.N1 = false;
        }
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final String m() {
        return "MediaCodecAudioRenderer";
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final boolean o() {
        if (!this.w1) {
            return false;
        }
        C2608sE c2608sE = this.G1;
        if (c2608sE.k()) {
            return c2608sE.K && !c2608sE.t();
        }
        return true;
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final boolean p() {
        return this.G1.t() || super.p();
    }

    @Override // com.google.android.gms.internal.ads.JE
    public final float r(float f, C1832aG[] c1832aGArr) {
        int iMax = -1;
        for (C1832aG c1832aG : c1832aGArr) {
            int i = c1832aG.D;
            if (i != -1) {
                iMax = Math.max(iMax, i);
            }
        }
        if (iMax == -1) {
            return -1.0f;
        }
        return iMax * f;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2650tD
    public final long zza() {
        if (this.h == 2) {
            k0();
        }
        return this.M1;
    }
}
