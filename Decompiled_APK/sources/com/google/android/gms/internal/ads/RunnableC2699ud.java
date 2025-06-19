package com.google.android.gms.internal.ads;

import android.os.SystemClock;
import android.widget.ImageView;

/* renamed from: com.google.android.gms.internal.ads.ud, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC2699ud implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ C2785wd b;

    public /* synthetic */ RunnableC2699ud(C2785wd c2785wd, int i) {
        this.a = i;
        this.b = c2785wd;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.c("firstFrameRendered", new String[0]);
                break;
            case 1:
                this.b.c("surfaceCreated", new String[0]);
                break;
            case 2:
                this.b.c("surfaceDestroyed", new String[0]);
                break;
            default:
                C2785wd c2785wd = this.b;
                if (c2785wd.h) {
                    ImageView imageView = c2785wd.q;
                    if (imageView.getParent() != null) {
                        c2785wd.b.removeView(imageView);
                    }
                }
                AbstractC2656td abstractC2656td = c2785wd.g;
                if (abstractC2656td != null && c2785wd.p != null) {
                    com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
                    jVar.k.getClass();
                    long jElapsedRealtime = SystemClock.elapsedRealtime();
                    if (abstractC2656td.getBitmap(c2785wd.p) != null) {
                        c2785wd.r = true;
                    }
                    jVar.k.getClass();
                    long jElapsedRealtime2 = SystemClock.elapsedRealtime() - jElapsedRealtime;
                    if (com.google.android.gms.ads.internal.util.A.m()) {
                        com.google.android.gms.ads.internal.util.A.l("Spinner frame grab took " + jElapsedRealtime2 + "ms");
                    }
                    if (jElapsedRealtime2 > c2785wd.f) {
                        com.google.android.gms.ads.internal.util.client.i.h("Spinner frame grab crossed jank threshold! Suspending spinner.");
                        c2785wd.k = false;
                        c2785wd.p = null;
                        B7 b7 = c2785wd.d;
                        if (b7 != null) {
                            b7.b("spinner_jank", Long.toString(jElapsedRealtime2));
                            break;
                        }
                    }
                }
                break;
        }
    }
}
