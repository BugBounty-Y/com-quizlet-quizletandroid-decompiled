package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.Gd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC1698Gd implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ long c;
    public final /* synthetic */ Object d;

    public /* synthetic */ RunnableC1698Gd(Object obj, boolean z, long j, int i) {
        this.a = i;
        this.d = obj;
        this.b = z;
        this.c = j;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                ((TextureViewSurfaceTextureListenerC1710Id) this.d).c.E0(this.c, this.b);
                break;
            case 1:
                ((InterfaceC2529qe) this.d).E0(this.c, this.b);
                break;
            default:
                ((C1669Be) this.d).a.E0(this.c, this.b);
                break;
        }
    }
}
