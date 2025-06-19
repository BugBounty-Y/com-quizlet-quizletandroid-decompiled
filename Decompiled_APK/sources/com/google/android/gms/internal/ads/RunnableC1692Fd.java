package com.google.android.gms.internal.ads;

import com.skydoves.balloon.internals.DefinitionKt;
import java.io.IOException;

/* renamed from: com.google.android.gms.internal.ads.Fd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC1692Fd implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ TextureViewSurfaceTextureListenerC1710Id b;

    public /* synthetic */ RunnableC1692Fd(TextureViewSurfaceTextureListenerC1710Id textureViewSurfaceTextureListenerC1710Id, int i) {
        this.a = i;
        this.b = textureViewSurfaceTextureListenerC1710Id;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                C2785wd c2785wd = this.b.g;
                if (c2785wd != null) {
                    c2785wd.h();
                    break;
                }
                break;
            case 1:
                C2785wd c2785wd2 = this.b.g;
                if (c2785wd2 != null) {
                    c2785wd2.f();
                    break;
                }
                break;
            case 2:
                TextureViewSurfaceTextureListenerC1710Id textureViewSurfaceTextureListenerC1710Id = this.b;
                C1686Ed c1686Ed = textureViewSurfaceTextureListenerC1710Id.b;
                boolean z = c1686Ed.e;
                float f = DefinitionKt.NO_Float_VALUE;
                float f2 = z ? 0.0f : c1686Ed.f;
                if (c1686Ed.c) {
                    f = f2;
                }
                C2143he c2143he = textureViewSurfaceTextureListenerC1710Id.i;
                if (c2143he == null) {
                    com.google.android.gms.ads.internal.util.client.i.h("Trying to set volume before player is initialized.");
                    break;
                } else {
                    try {
                        PD pd = c2143he.g;
                        if (pd != null) {
                            pd.d.a();
                            pd.c.B1(f);
                            break;
                        }
                    } catch (IOException e) {
                        com.google.android.gms.ads.internal.util.client.i.i("", e);
                        return;
                    }
                }
                break;
            case 3:
                C2785wd c2785wd3 = this.b.g;
                if (c2785wd3 != null) {
                    c2785wd3.i();
                    break;
                }
                break;
            case 4:
                C2785wd c2785wd4 = this.b.g;
                if (c2785wd4 != null) {
                    c2785wd4.e();
                    break;
                }
                break;
            case 5:
                C2785wd c2785wd5 = this.b.g;
                if (c2785wd5 != null) {
                    RunnableC2742vd runnableC2742vd = c2785wd5.e;
                    runnableC2742vd.b = false;
                    com.google.android.gms.ads.internal.util.B b = com.google.android.gms.ads.internal.util.F.l;
                    b.removeCallbacks(runnableC2742vd);
                    b.postDelayed(runnableC2742vd, 250L);
                    b.post(new RunnableC2699ud(c2785wd5, 1));
                    break;
                }
                break;
            case 6:
                C2785wd c2785wd6 = this.b.g;
                if (c2785wd6 != null) {
                    c2785wd6.d();
                    break;
                }
                break;
            default:
                C2785wd c2785wd7 = this.b.g;
                if (c2785wd7 != null) {
                    c2785wd7.g();
                    break;
                }
                break;
        }
    }
}
