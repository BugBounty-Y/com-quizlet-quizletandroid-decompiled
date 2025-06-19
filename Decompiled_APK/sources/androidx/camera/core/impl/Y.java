package androidx.camera.core.impl;

import android.media.LoudnessCodecController;
import android.media.MediaCodec;
import android.media.MediaCrypto;
import android.media.MediaFormat;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Trace;
import android.view.Surface;
import androidx.appcompat.app.HandlerC0048d;
import androidx.collection.C0210h;
import com.google.android.gms.internal.ads.AbstractC1795We;
import com.google.android.gms.internal.ads.BE;
import com.google.android.gms.internal.ads.CE;
import com.google.android.gms.internal.ads.DE;
import com.google.android.gms.internal.ads.Fp;
import com.google.android.gms.internal.ads.GE;
import com.google.android.gms.internal.ads.LC;
import com.google.android.gms.internal.ads.Lr;
import com.google.android.gms.internal.ads.RunnableC2104gj;
import com.google.android.gms.internal.ads.Yo;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class Y implements InterfaceC0161b0, GE {
    public int a;
    public boolean b;
    public Object c;
    public Object d;
    public Object e;
    public final Object f;

    public /* synthetic */ Y(MediaCodec mediaCodec, HandlerThread handlerThread, CE ce, Fp fp) {
        this.c = mediaCodec;
        this.d = new DE(handlerThread);
        this.e = ce;
        this.f = fp;
        this.a = 0;
    }

    public static void s(Y y, MediaFormat mediaFormat, Surface surface, int i) {
        Fp fp;
        LoudnessCodecController loudnessCodecController;
        DE de = (DE) y.d;
        AbstractC1795We.L(de.c == null);
        HandlerThread handlerThread = de.b;
        handlerThread.start();
        Handler handler = new Handler(handlerThread.getLooper());
        MediaCodec mediaCodec = (MediaCodec) y.c;
        mediaCodec.setCallback(de, handler);
        de.c = handler;
        Trace.beginSection("configureCodec");
        mediaCodec.configure(mediaFormat, surface, (MediaCrypto) null, i);
        Trace.endSection();
        CE ce = (CE) y.e;
        if (!ce.f) {
            HandlerThread handlerThread2 = ce.b;
            handlerThread2.start();
            ce.c = new HandlerC0048d(ce, handlerThread2.getLooper(), 3);
            ce.f = true;
        }
        Trace.beginSection("startCodec");
        mediaCodec.start();
        Trace.endSection();
        if (Build.VERSION.SDK_INT >= 35 && (fp = (Fp) y.f) != null && ((loudnessCodecController = (LoudnessCodecController) fp.c) == null || loudnessCodecController.addMediaCodec(mediaCodec))) {
            AbstractC1795We.L(((HashSet) fp.b).add(mediaCodec));
        }
        y.a = 1;
    }

    public static String t(int i, String str) {
        StringBuilder sb = new StringBuilder(str);
        if (i == 1) {
            sb.append("Audio");
        } else if (i == 2) {
            sb.append("Video");
        } else {
            sb.append("Unknown(");
            sb.append(i);
            sb.append(")");
        }
        return sb.toString();
    }

    @Override // com.google.android.gms.internal.ads.GE
    public MediaFormat a() {
        MediaFormat mediaFormat;
        DE de = (DE) this.d;
        synchronized (de.a) {
            try {
                mediaFormat = de.h;
                if (mediaFormat == null) {
                    throw new IllegalStateException();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return mediaFormat;
    }

    @Override // androidx.camera.core.impl.InterfaceC0161b0
    public void b(InterfaceC0159a0 interfaceC0159a0) {
        synchronized (this.c) {
            s0 s0Var = (s0) ((HashMap) this.e).remove(interfaceC0159a0);
            if (s0Var != null) {
                s0Var.c.set(false);
                ((CopyOnWriteArraySet) this.f).remove(s0Var);
            }
        }
    }

    @Override // androidx.camera.core.impl.InterfaceC0161b0
    public void c(Executor executor, InterfaceC0159a0 interfaceC0159a0) {
        s0 s0Var;
        synchronized (this.c) {
            s0 s0Var2 = (s0) ((HashMap) this.e).remove(interfaceC0159a0);
            if (s0Var2 != null) {
                s0Var2.c.set(false);
                ((CopyOnWriteArraySet) this.f).remove(s0Var2);
            }
            s0Var = new s0((AtomicReference) this.d, executor, interfaceC0159a0);
            ((HashMap) this.e).put(interfaceC0159a0, s0Var);
            ((CopyOnWriteArraySet) this.f).add(s0Var);
        }
        s0Var.a(0);
    }

    @Override // com.google.android.gms.internal.ads.GE
    public ByteBuffer d(int i) {
        return ((MediaCodec) this.c).getInputBuffer(i);
    }

    @Override // com.google.android.gms.internal.ads.GE
    public ByteBuffer e(int i) {
        return ((MediaCodec) this.c).getOutputBuffer(i);
    }

    @Override // com.google.android.gms.internal.ads.GE
    public void f(Surface surface) {
        ((MediaCodec) this.c).setOutputSurface(surface);
    }

    @Override // com.google.android.gms.internal.ads.GE
    public boolean g(Lr lr) {
        DE de = (DE) this.d;
        synchronized (de.a) {
            de.o = lr;
        }
        return true;
    }

    @Override // com.google.android.gms.internal.ads.GE
    public void h(int i, long j) {
        ((MediaCodec) this.c).releaseOutputBuffer(i, j);
    }

    @Override // com.google.android.gms.internal.ads.GE
    public void i() {
        ((CE) this.e).a();
        MediaCodec mediaCodec = (MediaCodec) this.c;
        mediaCodec.flush();
        DE de = (DE) this.d;
        synchronized (de.a) {
            de.l++;
            Handler handler = de.c;
            String str = Yo.a;
            handler.post(new RunnableC2104gj(de, 27));
        }
        mediaCodec.start();
    }

    @Override // com.google.android.gms.internal.ads.GE
    public void j(int i) {
        ((MediaCodec) this.c).setVideoScalingMode(i);
    }

    @Override // com.google.android.gms.internal.ads.GE
    public int k(MediaCodec.BufferInfo bufferInfo) {
        ((CE) this.e).b();
        DE de = (DE) this.d;
        synchronized (de.a) {
            try {
                IllegalStateException illegalStateException = de.n;
                if (illegalStateException != null) {
                    de.n = null;
                    throw illegalStateException;
                }
                MediaCodec.CodecException codecException = de.j;
                if (codecException != null) {
                    de.j = null;
                    throw codecException;
                }
                MediaCodec.CryptoException cryptoException = de.k;
                if (cryptoException != null) {
                    de.k = null;
                    throw cryptoException;
                }
                if (de.l > 0 || de.m) {
                    return -1;
                }
                C0210h c0210h = de.e;
                int i = c0210h.a;
                int i2 = c0210h.b;
                if (i == i2) {
                    return -1;
                }
                if (i == i2) {
                    throw new ArrayIndexOutOfBoundsException();
                }
                int i3 = c0210h.c[i];
                c0210h.a = c0210h.d & (i + 1);
                if (i3 >= 0) {
                    AbstractC1795We.p(de.h);
                    MediaCodec.BufferInfo bufferInfo2 = (MediaCodec.BufferInfo) de.f.remove();
                    bufferInfo.set(bufferInfo2.offset, bufferInfo2.size, bufferInfo2.presentationTimeUs, bufferInfo2.flags);
                } else if (i3 == -2) {
                    de.h = (MediaFormat) de.g.remove();
                    i3 = -2;
                }
                return i3;
            } finally {
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.GE
    public void l() {
        Fp fp;
        Fp fp2;
        try {
            try {
                if (this.a == 1) {
                    CE ce = (CE) this.e;
                    if (ce.f) {
                        ce.a();
                        ce.b.quit();
                    }
                    ce.f = false;
                    DE de = (DE) this.d;
                    synchronized (de.a) {
                        de.m = true;
                        de.b.quit();
                        de.a();
                    }
                }
                this.a = 2;
            } finally {
                if (!this.b) {
                    int i = Build.VERSION.SDK_INT;
                    if (i >= 30 && i < 33) {
                        ((MediaCodec) this.c).stop();
                    }
                    if (i >= 35 && (fp2 = (Fp) this.f) != null) {
                        fp2.f((MediaCodec) this.c);
                    }
                    ((MediaCodec) this.c).release();
                    this.b = true;
                }
            }
        } catch (Throwable th) {
            if (Build.VERSION.SDK_INT >= 35 && (fp = (Fp) this.f) != null) {
                fp.f((MediaCodec) this.c);
            }
            ((MediaCodec) this.c).release();
            this.b = true;
            throw th;
        }
    }

    @Override // com.google.android.gms.internal.ads.GE
    public void m(int i) {
        ((MediaCodec) this.c).releaseOutputBuffer(i, false);
    }

    @Override // com.google.android.gms.internal.ads.GE
    public void n(long j, int i, int i2, int i3) {
        CE ce = (CE) this.e;
        ce.b();
        BE beC = CE.c();
        beC.a = i;
        beC.b = i2;
        beC.d = j;
        beC.e = i3;
        HandlerC0048d handlerC0048d = ce.c;
        String str = Yo.a;
        handlerC0048d.obtainMessage(1, beC).sendToTarget();
    }

    @Override // com.google.android.gms.internal.ads.GE
    public void o(Bundle bundle) {
        CE ce = (CE) this.e;
        ce.b();
        HandlerC0048d handlerC0048d = ce.c;
        String str = Yo.a;
        handlerC0048d.obtainMessage(4, bundle).sendToTarget();
    }

    @Override // com.google.android.gms.internal.ads.GE
    public void p(int i, LC lc, long j) {
        int length;
        int length2;
        int length3;
        int length4;
        CE ce = (CE) this.e;
        ce.b();
        BE beC = CE.c();
        beC.a = i;
        beC.b = 0;
        beC.d = j;
        beC.e = 0;
        int i2 = lc.f;
        MediaCodec.CryptoInfo cryptoInfo = beC.c;
        cryptoInfo.numSubSamples = i2;
        int[] iArr = lc.d;
        int[] iArrCopyOf = cryptoInfo.numBytesOfClearData;
        if (iArr != null) {
            if (iArrCopyOf == null || iArrCopyOf.length < (length4 = iArr.length)) {
                iArrCopyOf = Arrays.copyOf(iArr, iArr.length);
            } else {
                System.arraycopy(iArr, 0, iArrCopyOf, 0, length4);
            }
        }
        cryptoInfo.numBytesOfClearData = iArrCopyOf;
        int[] iArr2 = lc.e;
        int[] iArrCopyOf2 = cryptoInfo.numBytesOfEncryptedData;
        if (iArr2 != null) {
            if (iArrCopyOf2 == null || iArrCopyOf2.length < (length3 = iArr2.length)) {
                iArrCopyOf2 = Arrays.copyOf(iArr2, iArr2.length);
            } else {
                System.arraycopy(iArr2, 0, iArrCopyOf2, 0, length3);
            }
        }
        cryptoInfo.numBytesOfEncryptedData = iArrCopyOf2;
        byte[] bArr = lc.b;
        byte[] bArrCopyOf = cryptoInfo.key;
        if (bArr != null) {
            if (bArrCopyOf == null || bArrCopyOf.length < (length2 = bArr.length)) {
                bArrCopyOf = Arrays.copyOf(bArr, bArr.length);
            } else {
                System.arraycopy(bArr, 0, bArrCopyOf, 0, length2);
            }
        }
        bArrCopyOf.getClass();
        cryptoInfo.key = bArrCopyOf;
        byte[] bArr2 = lc.a;
        byte[] bArrCopyOf2 = cryptoInfo.iv;
        if (bArr2 != null) {
            if (bArrCopyOf2 == null || bArrCopyOf2.length < (length = bArr2.length)) {
                bArrCopyOf2 = Arrays.copyOf(bArr2, bArr2.length);
            } else {
                System.arraycopy(bArr2, 0, bArrCopyOf2, 0, length);
            }
        }
        bArrCopyOf2.getClass();
        cryptoInfo.iv = bArrCopyOf2;
        cryptoInfo.mode = lc.c;
        cryptoInfo.setPattern(new MediaCodec.CryptoInfo.Pattern(lc.g, lc.h));
        HandlerC0048d handlerC0048d = ce.c;
        String str = Yo.a;
        handlerC0048d.obtainMessage(2, beC).sendToTarget();
    }

    public boolean q(int i, int i2) {
        androidx.compose.runtime.collection.b bVar = (androidx.compose.runtime.collection.b) this.d;
        int i3 = this.a;
        androidx.compose.ui.o oVar = (androidx.compose.ui.o) bVar.a[i + i3];
        androidx.compose.ui.o oVar2 = (androidx.compose.ui.o) ((androidx.compose.runtime.collection.b) this.e).a[i3 + i2];
        androidx.compose.ui.node.W w = androidx.compose.ui.node.X.a;
        return Intrinsics.b(oVar, oVar2) || oVar.getClass() == oVar2.getClass();
    }

    public androidx.camera.core.impl.utils.futures.k r() {
        Object obj = ((AtomicReference) this.d).get();
        if (!(obj instanceof AbstractC0167f)) {
            return androidx.camera.core.impl.utils.futures.i.c(obj);
        }
        ((AbstractC0167f) obj).getClass();
        return new androidx.camera.core.impl.utils.futures.k(null, 1);
    }

    @Override // com.google.android.gms.internal.ads.GE
    public int zza() {
        ((CE) this.e).b();
        DE de = (DE) this.d;
        synchronized (de.a) {
            try {
                IllegalStateException illegalStateException = de.n;
                if (illegalStateException != null) {
                    de.n = null;
                    throw illegalStateException;
                }
                MediaCodec.CodecException codecException = de.j;
                if (codecException != null) {
                    de.j = null;
                    throw codecException;
                }
                MediaCodec.CryptoException cryptoException = de.k;
                if (cryptoException != null) {
                    de.k = null;
                    throw cryptoException;
                }
                int i = -1;
                if (de.l > 0 || de.m) {
                    return -1;
                }
                C0210h c0210h = de.d;
                int i2 = c0210h.a;
                int i3 = c0210h.b;
                if (!(i2 == i3)) {
                    if (i2 == i3) {
                        throw new ArrayIndexOutOfBoundsException();
                    }
                    i = c0210h.c[i2];
                    c0210h.a = (i2 + 1) & c0210h.d;
                }
                return i;
            } finally {
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.GE
    public void zzi() {
        ((MediaCodec) this.c).detachOutputSurface();
    }

    public Y(f0 f0Var) {
        this.c = new Object();
        this.a = 0;
        this.b = false;
        this.e = new HashMap();
        this.f = new CopyOnWriteArraySet();
        this.d = new AtomicReference(f0Var);
    }

    public Y(androidx.compose.ui.node.V v, androidx.compose.ui.p pVar, int i, androidx.compose.runtime.collection.b bVar, androidx.compose.runtime.collection.b bVar2, boolean z) {
        this.f = v;
        this.c = pVar;
        this.a = i;
        this.d = bVar;
        this.e = bVar2;
        this.b = z;
    }
}
