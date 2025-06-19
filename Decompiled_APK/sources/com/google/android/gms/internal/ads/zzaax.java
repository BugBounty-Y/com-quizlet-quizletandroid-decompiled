package com.google.android.gms.internal.ads;

import android.graphics.SurfaceTexture;
import android.os.Handler;
import android.view.Surface;

/* loaded from: classes2.dex */
public final class zzaax extends Surface {
    public static int d;
    public static boolean e;
    public final boolean a;
    public final HandlerThreadC2336m b;
    public boolean c;

    public /* synthetic */ zzaax(HandlerThreadC2336m handlerThreadC2336m, SurfaceTexture surfaceTexture, boolean z) {
        super(surfaceTexture);
        this.b = handlerThreadC2336m;
        this.a = z;
    }

    public static synchronized boolean a() {
        try {
            if (!e) {
                d = AbstractC1972di.G("EGL_EXT_protected_content") ? AbstractC1972di.G("EGL_KHR_surfaceless_context") ? 1 : 2 : 0;
                e = true;
            }
        } catch (Throwable th) {
            throw th;
        }
        return d != 0;
    }

    @Override // android.view.Surface
    public final void release() {
        super.release();
        HandlerThreadC2336m handlerThreadC2336m = this.b;
        synchronized (handlerThreadC2336m) {
            try {
                if (!this.c) {
                    Handler handler = handlerThreadC2336m.b;
                    handler.getClass();
                    handler.sendEmptyMessage(2);
                    this.c = true;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
