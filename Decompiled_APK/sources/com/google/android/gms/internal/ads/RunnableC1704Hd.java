package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.Hd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC1704Hd implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ TextureViewSurfaceTextureListenerC1710Id b;
    public final /* synthetic */ String c;

    public /* synthetic */ RunnableC1704Hd(TextureViewSurfaceTextureListenerC1710Id textureViewSurfaceTextureListenerC1710Id, String str, int i) {
        this.a = i;
        this.b = textureViewSurfaceTextureListenerC1710Id;
        this.c = str;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                C2785wd c2785wd = this.b.g;
                if (c2785wd != null) {
                    c2785wd.c("exception", "what", "ExoPlayerAdapter exception", "extra", this.c);
                    break;
                }
                break;
            default:
                C2785wd c2785wd2 = this.b.g;
                if (c2785wd2 != null) {
                    c2785wd2.c("error", "what", "ExoPlayerAdapter error", "extra", this.c);
                    break;
                }
                break;
        }
    }
}
