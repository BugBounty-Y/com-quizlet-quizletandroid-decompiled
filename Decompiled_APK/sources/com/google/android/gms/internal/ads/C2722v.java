package com.google.android.gms.internal.ads;

import android.content.Context;
import android.hardware.display.DisplayManager;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.view.Surface;
import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: com.google.android.gms.internal.ads.v, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2722v {
    public final C2293l a;
    public final C2851y b;
    public boolean c;
    public long f;
    public boolean i;
    public boolean l;
    public boolean m;
    public int d = 0;
    public long e = -9223372036854775807L;
    public long g = -9223372036854775807L;
    public long h = -9223372036854775807L;
    public float j = 1.0f;
    public C1847ao k = C1847ao.a;

    public C2722v(Context context, C2293l c2293l) {
        this.a = c2293l;
        this.b = new C2851y(context);
    }

    /* JADX WARN: Code restructure failed: missing block: B:71:0x013e, code lost:
    
        if (r4 > 100000) goto L80;
     */
    /* JADX WARN: Code restructure failed: missing block: B:76:0x0149, code lost:
    
        if (r29 >= r33) goto L80;
     */
    /* JADX WARN: Code restructure failed: missing block: B:79:0x014e, code lost:
    
        if (r26.c != false) goto L80;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:101:0x01ce  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x00ae  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00b0  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int a(long r27, long r29, long r31, long r33, boolean r35, boolean r36, com.google.android.gms.internal.ads.C2679u r37) {
        /*
            Method dump skipped, instructions count: 581
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2722v.a(long, long, long, long, boolean, boolean, com.google.android.gms.internal.ads.u):int");
    }

    public final void b() {
        this.c = true;
        this.k.getClass();
        this.f = Yo.t(SystemClock.elapsedRealtime());
        C2851y c2851y = this.b;
        c2851y.d = true;
        c2851y.m = 0L;
        c2851y.p = -1L;
        c2851y.n = -1L;
        C2765w c2765w = c2851y.b;
        if (c2765w != null) {
            ChoreographerFrameCallbackC2808x choreographerFrameCallbackC2808x = c2851y.c;
            choreographerFrameCallbackC2808x.getClass();
            choreographerFrameCallbackC2808x.b.sendEmptyMessage(2);
            Looper looperMyLooper = Looper.myLooper();
            AbstractC1795We.p(looperMyLooper);
            Handler handler = new Handler(looperMyLooper, null);
            DisplayManager displayManager = c2765w.a;
            displayManager.registerDisplayListener(c2765w, handler);
            C2851y.a(c2765w.b, displayManager.getDisplay(0));
        }
        c2851y.d(false);
    }

    public final void c() {
        this.c = false;
        this.h = -9223372036854775807L;
        C2851y c2851y = this.b;
        c2851y.d = false;
        C2765w c2765w = c2851y.b;
        if (c2765w != null) {
            c2765w.a.unregisterDisplayListener(c2765w);
            ChoreographerFrameCallbackC2808x choreographerFrameCallbackC2808x = c2851y.c;
            choreographerFrameCallbackC2808x.getClass();
            choreographerFrameCallbackC2808x.b.sendEmptyMessage(3);
        }
        c2851y.b();
    }

    public final void d(int i) {
        if (i == 0) {
            this.d = 1;
        } else if (i != 1) {
            this.d = Math.min(this.d, 2);
        } else {
            this.d = 0;
        }
    }

    public final void e(float f) {
        C2851y c2851y = this.b;
        c2851y.f = f;
        C2165i c2165i = c2851y.a;
        c2165i.a.b();
        c2165i.b.b();
        c2165i.c = false;
        c2165i.d = -9223372036854775807L;
        c2165i.e = 0;
        c2851y.c();
    }

    public final void f(Surface surface) {
        this.l = surface != null;
        this.m = false;
        C2851y c2851y = this.b;
        if (c2851y.e != surface) {
            c2851y.b();
            c2851y.e = surface;
            c2851y.d(true);
        }
        this.d = Math.min(this.d, 1);
    }

    public final void g(float f) {
        AbstractC1795We.B(f > DefinitionKt.NO_Float_VALUE);
        if (f == this.j) {
            return;
        }
        this.j = f;
        C2851y c2851y = this.b;
        c2851y.i = f;
        c2851y.m = 0L;
        c2851y.p = -1L;
        c2851y.n = -1L;
        c2851y.d(false);
    }

    public final boolean h(boolean z) {
        if (z && (this.d == 3 || (!this.l && this.m))) {
            this.h = -9223372036854775807L;
            return true;
        }
        if (this.h == -9223372036854775807L) {
            return false;
        }
        this.k.getClass();
        if (SystemClock.elapsedRealtime() < this.h) {
            return true;
        }
        this.h = -9223372036854775807L;
        return false;
    }
}
