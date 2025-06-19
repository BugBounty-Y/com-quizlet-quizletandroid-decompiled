package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.qd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class RunnableC2528qd implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ TextureViewSurfaceTextureListenerC2613sd b;

    public /* synthetic */ RunnableC2528qd(TextureViewSurfaceTextureListenerC2613sd textureViewSurfaceTextureListenerC2613sd, int i) {
        this.a = i;
        this.b = textureViewSurfaceTextureListenerC2613sd;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                C2785wd c2785wd = this.b.q;
                if (c2785wd != null) {
                    c2785wd.d();
                    break;
                }
                break;
            case 1:
                C2785wd c2785wd2 = this.b.q;
                if (c2785wd2 != null) {
                    RunnableC2742vd runnableC2742vd = c2785wd2.e;
                    runnableC2742vd.b = false;
                    com.google.android.gms.ads.internal.util.B b = com.google.android.gms.ads.internal.util.F.l;
                    b.removeCallbacks(runnableC2742vd);
                    b.postDelayed(runnableC2742vd, 250L);
                    b.post(new RunnableC2699ud(c2785wd2, 1));
                    break;
                }
                break;
            case 2:
                TextureViewSurfaceTextureListenerC2613sd textureViewSurfaceTextureListenerC2613sd = this.b;
                C2785wd c2785wd3 = textureViewSurfaceTextureListenerC2613sd.q;
                if (c2785wd3 != null) {
                    c2785wd3.e();
                    textureViewSurfaceTextureListenerC2613sd.q.i();
                    break;
                }
                break;
            case 3:
                TextureViewSurfaceTextureListenerC2613sd textureViewSurfaceTextureListenerC2613sd2 = this.b;
                C2785wd c2785wd4 = textureViewSurfaceTextureListenerC2613sd2.q;
                if (c2785wd4 != null) {
                    if (!textureViewSurfaceTextureListenerC2613sd2.r) {
                        c2785wd4.h();
                        textureViewSurfaceTextureListenerC2613sd2.r = true;
                    }
                    textureViewSurfaceTextureListenerC2613sd2.q.f();
                    break;
                }
                break;
            default:
                C2785wd c2785wd5 = this.b.q;
                if (c2785wd5 != null) {
                    c2785wd5.e();
                    break;
                }
                break;
        }
    }
}
