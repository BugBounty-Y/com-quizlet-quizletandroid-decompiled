package com.google.android.gms.internal.ads;

import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.os.RemoteException;
import android.os.SystemClock;
import android.os.Trace;
import java.io.FileNotFoundException;
import java.io.IOException;

/* renamed from: com.google.android.gms.internal.ads.gG, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class HandlerC2094gG extends Handler implements Runnable {
    public final C2566rF a;
    public C2695uF b;
    public IOException c;
    public int d;
    public Thread e;
    public boolean f;
    public volatile boolean g;
    public final /* synthetic */ C2326lq h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public HandlerC2094gG(C2326lq c2326lq, Looper looper, C2566rF c2566rF, C2695uF c2695uF, long j) {
        super(looper);
        this.h = c2326lq;
        this.a = c2566rF;
        this.b = c2695uF;
    }

    public final void a(boolean z) {
        this.g = z;
        this.c = null;
        if (hasMessages(1)) {
            this.f = true;
            removeMessages(1);
            if (!z) {
                sendEmptyMessage(2);
            }
        } else {
            synchronized (this) {
                try {
                    this.f = true;
                    this.a.g = true;
                    Thread thread = this.e;
                    if (thread != null) {
                        thread.interrupt();
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
        }
        if (z) {
            this.h.c = null;
            SystemClock.elapsedRealtime();
            C2695uF c2695uF = this.b;
            c2695uF.getClass();
            c2695uF.g(this.a, true);
            this.b = null;
        }
    }

    public final void b() {
        YE ye;
        SystemClock.elapsedRealtime();
        C2695uF c2695uF = this.b;
        c2695uF.getClass();
        int i = this.d;
        C2566rF c2566rF = this.a;
        C2563rC c2563rC = c2566rF.b;
        if (i == 0) {
            Uri uri = c2566rF.j.a;
            ye = new YE();
        } else {
            Uri uri2 = c2563rC.b;
            ye = new YE();
        }
        androidx.compose.animation.core.S0 s0 = new androidx.compose.animation.core.S0(-1, null, Yo.w(c2566rF.i), Yo.w(c2695uF.y));
        C2866yE c2866yE = c2695uF.d;
        c2866yE.a(new As(c2866yE, ye, s0, i));
        this.c = null;
        C2326lq c2326lq = this.h;
        ExecutorC1859b executorC1859b = (ExecutorC1859b) c2326lq.b;
        HandlerC2094gG handlerC2094gG = (HandlerC2094gG) c2326lq.c;
        handlerC2094gG.getClass();
        executorC1859b.execute(handlerC2094gG);
    }

    @Override // android.os.Handler
    public final void handleMessage(Message message) throws RemoteException, IOException {
        long jMin;
        C2426o3 c2426o3;
        InterfaceC2122h0 interfaceC2122h0;
        boolean z = true;
        if (this.g) {
            return;
        }
        int i = message.what;
        if (i == 1) {
            b();
            return;
        }
        if (i == 4) {
            throw ((Error) message.obj);
        }
        C2326lq c2326lq = this.h;
        c2326lq.c = null;
        SystemClock.elapsedRealtime();
        C2695uF c2695uF = this.b;
        c2695uF.getClass();
        if (this.f) {
            c2695uF.g(this.a, false);
            return;
        }
        int i2 = message.what;
        if (i2 == 2) {
            try {
                c2695uF.l(this.a);
                return;
            } catch (RuntimeException e) {
                AbstractC2096gb.A("LoadTask", "Unexpected exception handling load completed", e);
                this.h.d = new zzzs(e);
                return;
            }
        }
        if (i2 != 3) {
            return;
        }
        IOException iOException = (IOException) message.obj;
        this.c = iOException;
        int i3 = this.d;
        this.d = i3 + 1;
        C2566rF c2566rF = this.a;
        Uri uri = c2566rF.b.b;
        YE ye = new YE();
        String str = Yo.a;
        if ((iOException instanceof zzaz) || (iOException instanceof FileNotFoundException) || (iOException instanceof zzgw) || (iOException instanceof zzzs)) {
            jMin = -9223372036854775807L;
            break;
        }
        for (Throwable cause = iOException; cause != null; cause = cause.getCause()) {
            if ((cause instanceof zzgh) && ((zzgh) cause).a == 2008) {
                jMin = -9223372036854775807L;
                break;
            }
        }
        jMin = Math.min(i3 * 1000, 5000);
        if (jMin == -9223372036854775807L) {
            c2426o3 = C2326lq.g;
        } else {
            int iS = c2695uF.s();
            int i4 = iS > c2695uF.J ? 1 : 0;
            if (c2695uF.F || !((interfaceC2122h0 = c2695uF.x) == null || interfaceC2122h0.zza() == -9223372036854775807L)) {
                c2695uF.J = iS;
            } else {
                boolean z2 = c2695uF.t;
                if (!z2 || c2695uF.B()) {
                    c2695uF.C = z2;
                    c2695uF.G = 0L;
                    c2695uF.J = 0;
                    C2910zF[] c2910zFArr = c2695uF.q;
                    int length = c2910zFArr.length;
                    int i5 = 0;
                    while (i5 < length) {
                        c2910zFArr[i5].m(false);
                        i5++;
                        z = z;
                    }
                    c2566rF.f.a = 0L;
                    c2566rF.i = 0L;
                    c2566rF.h = z;
                    c2566rF.l = false;
                } else {
                    c2695uF.I = true;
                    c2426o3 = C2326lq.f;
                }
            }
            c2426o3 = new C2426o3(i4, jMin);
        }
        int i6 = c2426o3.a;
        boolean z3 = i6 == 0 || i6 == 1;
        androidx.compose.animation.core.S0 s0 = new androidx.compose.animation.core.S0(-1, null, Yo.w(c2566rF.i), Yo.w(c2695uF.y));
        C2866yE c2866yE = c2695uF.d;
        c2866yE.a(new Bs(c2866yE, ye, s0, iOException, !z3));
        int i7 = c2426o3.a;
        if (i7 == 3) {
            c2326lq.d = this.c;
            return;
        }
        if (i7 != 2) {
            if (i7 == 1) {
                this.d = 1;
            }
            long jMin2 = c2426o3.b;
            if (jMin2 == -9223372036854775807L) {
                jMin2 = Math.min((this.d - 1) * 1000, 5000);
            }
            C2326lq c2326lq2 = this.h;
            AbstractC1795We.L(((HandlerC2094gG) c2326lq2.c) == null);
            c2326lq2.c = this;
            if (jMin2 > 0) {
                sendEmptyMessageDelayed(1, jMin2);
            } else {
                b();
            }
        }
    }

    @Override // java.lang.Runnable
    public final void run() {
        boolean z;
        try {
            synchronized (this) {
                z = this.f;
                this.e = Thread.currentThread();
            }
            if (!z) {
                C2566rF c2566rF = this.a;
                Trace.beginSection("load:".concat(c2566rF.getClass().getSimpleName()));
                try {
                    c2566rF.a();
                    Trace.endSection();
                } catch (Throwable th) {
                    Trace.endSection();
                    throw th;
                }
            }
            synchronized (this) {
                this.e = null;
                Thread.interrupted();
            }
            if (this.g) {
                return;
            }
            sendEmptyMessage(2);
        } catch (IOException e) {
            if (this.g) {
                return;
            }
            obtainMessage(3, e).sendToTarget();
        } catch (Exception e2) {
            if (this.g) {
                return;
            }
            AbstractC2096gb.A("LoadTask", "Unexpected exception loading stream", e2);
            obtainMessage(3, new zzzs(e2)).sendToTarget();
        } catch (OutOfMemoryError e3) {
            if (this.g) {
                return;
            }
            AbstractC2096gb.A("LoadTask", "OutOfMemory error loading stream", e3);
            obtainMessage(3, new zzzs(e3)).sendToTarget();
        } catch (Error e4) {
            if (!this.g) {
                AbstractC2096gb.A("LoadTask", "Unexpected error loading stream", e4);
                obtainMessage(4, e4).sendToTarget();
            }
            throw e4;
        }
    }
}
