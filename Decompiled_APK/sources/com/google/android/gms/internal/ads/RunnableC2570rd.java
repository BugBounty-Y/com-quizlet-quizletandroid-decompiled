package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.rd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class RunnableC2570rd implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;
    public final /* synthetic */ AbstractC2656td d;

    public /* synthetic */ RunnableC2570rd(AbstractC2656td abstractC2656td, int i, int i2, int i3) {
        this.a = i3;
        this.b = i;
        this.c = i2;
        this.d = abstractC2656td;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                C2785wd c2785wd = ((TextureViewSurfaceTextureListenerC2613sd) this.d).q;
                if (c2785wd != null) {
                    c2785wd.j(this.b, this.c);
                    break;
                }
                break;
            default:
                C2785wd c2785wd2 = ((TextureViewSurfaceTextureListenerC1710Id) this.d).g;
                if (c2785wd2 != null) {
                    c2785wd2.j(this.b, this.c);
                    break;
                }
                break;
        }
    }
}
