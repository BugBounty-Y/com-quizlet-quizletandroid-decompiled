package com.google.android.gms.internal.ads;

import android.media.MediaCodec;
import android.os.HandlerThread;
import androidx.appcompat.app.HandlerC0048d;
import java.util.ArrayDeque;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class CE {
    public static final ArrayDeque g = new ArrayDeque();
    public static final Object h = new Object();
    public final MediaCodec a;
    public final HandlerThread b;
    public HandlerC0048d c;
    public final AtomicReference d;
    public final C1973dj e;
    public boolean f;

    public CE(MediaCodec mediaCodec, HandlerThread handlerThread) {
        C1973dj c1973dj = new C1973dj();
        this.a = mediaCodec;
        this.b = handlerThread;
        this.e = c1973dj;
        this.d = new AtomicReference();
    }

    public static BE c() {
        ArrayDeque arrayDeque = g;
        synchronized (arrayDeque) {
            try {
                if (arrayDeque.isEmpty()) {
                    return new BE();
                }
                return (BE) arrayDeque.removeFirst();
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final void a() {
        if (this.f) {
            try {
                HandlerC0048d handlerC0048d = this.c;
                if (handlerC0048d == null) {
                    throw null;
                }
                handlerC0048d.removeCallbacksAndMessages(null);
                C1973dj c1973dj = this.e;
                synchronized (c1973dj) {
                    c1973dj.a = false;
                }
                HandlerC0048d handlerC0048d2 = this.c;
                if (handlerC0048d2 == null) {
                    throw null;
                }
                handlerC0048d2.obtainMessage(3).sendToTarget();
                synchronized (c1973dj) {
                    while (!c1973dj.a) {
                        c1973dj.wait();
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
        }
    }

    public final void b() {
        RuntimeException runtimeException = (RuntimeException) this.d.getAndSet(null);
        if (runtimeException != null) {
            throw runtimeException;
        }
    }
}
