package com.google.android.gms.internal.ads;

import android.content.Context;
import android.hardware.display.DisplayManager;
import android.os.Build;
import android.view.Display;
import android.view.Surface;
import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: com.google.android.gms.internal.ads.y, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2851y {
    public final C2165i a;
    public final C2765w b;
    public final ChoreographerFrameCallbackC2808x c;
    public boolean d;
    public Surface e;
    public float f;
    public float g;
    public float h;
    public float i;
    public int j;
    public long k;
    public long l;
    public long m;
    public long n;
    public long o;
    public long p;
    public long q;

    public C2851y(Context context) {
        DisplayManager displayManager;
        C2165i c2165i = new C2165i();
        c2165i.a = new C2121h();
        c2165i.b = new C2121h();
        c2165i.d = -9223372036854775807L;
        this.a = c2165i;
        C2765w c2765w = (context == null || (displayManager = (DisplayManager) context.getSystemService("display")) == null) ? null : new C2765w(this, displayManager);
        this.b = c2765w;
        this.c = c2765w != null ? ChoreographerFrameCallbackC2808x.e : null;
        this.k = -9223372036854775807L;
        this.l = -9223372036854775807L;
        this.f = -1.0f;
        this.i = 1.0f;
        this.j = 0;
    }

    public static /* bridge */ /* synthetic */ void a(C2851y c2851y, Display display) {
        if (display != null) {
            long refreshRate = (long) (1.0E9d / display.getRefreshRate());
            c2851y.k = refreshRate;
            c2851y.l = (refreshRate * 80) / 100;
        } else {
            AbstractC2096gb.J("VideoFrameReleaseHelper", "Unable to query display refresh rate");
            c2851y.k = -9223372036854775807L;
            c2851y.l = -9223372036854775807L;
        }
    }

    public final void b() {
        Surface surface;
        if (Build.VERSION.SDK_INT < 30 || (surface = this.e) == null || this.j == Integer.MIN_VALUE || this.h == DefinitionKt.NO_Float_VALUE) {
            return;
        }
        this.h = DefinitionKt.NO_Float_VALUE;
        try {
            surface.setFrameRate(DefinitionKt.NO_Float_VALUE, 0);
        } catch (IllegalStateException e) {
            AbstractC2096gb.A("VideoFrameReleaseHelper", "Failed to call Surface.setFrameRate", e);
        }
    }

    public final void c() {
        float f;
        if (Build.VERSION.SDK_INT < 30 || this.e == null) {
            return;
        }
        C2165i c2165i = this.a;
        if (!c2165i.a.c()) {
            f = this.f;
        } else if (c2165i.a.c()) {
            f = (float) (1.0E9d / (c2165i.a.e != 0 ? r2.f / r4 : 0L));
        } else {
            f = -1.0f;
        }
        float f2 = this.g;
        if (f != f2) {
            if (f != -1.0f && f2 != -1.0f) {
                float f3 = 1.0f;
                if (c2165i.a.c()) {
                    if ((c2165i.a.c() ? c2165i.a.f : -9223372036854775807L) >= 5000000000L) {
                        f3 = 0.02f;
                    }
                }
                if (Math.abs(f - this.g) < f3) {
                    return;
                }
            } else if (f == -1.0f && c2165i.e < 30) {
                return;
            }
            this.g = f;
            d(false);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x0022  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void d(boolean r5) {
        /*
            r4 = this;
            int r0 = android.os.Build.VERSION.SDK_INT
            r1 = 30
            if (r0 < r1) goto L40
            android.view.Surface r0 = r4.e
            if (r0 == 0) goto L40
            int r1 = r4.j
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            if (r1 != r2) goto L11
            goto L40
        L11:
            boolean r1 = r4.d
            r2 = 0
            if (r1 == 0) goto L22
            float r1 = r4.g
            r3 = -1082130432(0xffffffffbf800000, float:-1.0)
            int r3 = (r1 > r3 ? 1 : (r1 == r3 ? 0 : -1))
            if (r3 == 0) goto L22
            float r3 = r4.i
            float r1 = r1 * r3
            goto L23
        L22:
            r1 = r2
        L23:
            if (r5 != 0) goto L2b
            float r5 = r4.h
            int r5 = (r5 > r1 ? 1 : (r5 == r1 ? 0 : -1))
            if (r5 == 0) goto L40
        L2b:
            r4.h = r1
            int r5 = (r1 > r2 ? 1 : (r1 == r2 ? 0 : -1))
            if (r5 != 0) goto L33
            r5 = 0
            goto L34
        L33:
            r5 = 1
        L34:
            androidx.core.view.A0.o(r0, r1, r5)     // Catch: java.lang.IllegalStateException -> L38
            return
        L38:
            r5 = move-exception
            java.lang.String r0 = "VideoFrameReleaseHelper"
            java.lang.String r1 = "Failed to call Surface.setFrameRate"
            com.google.android.gms.internal.ads.AbstractC2096gb.A(r0, r1, r5)
        L40:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2851y.d(boolean):void");
    }
}
