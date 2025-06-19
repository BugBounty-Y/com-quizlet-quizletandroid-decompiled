package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.uk, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC2706uk implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ C2749vk b;

    public /* synthetic */ RunnableC2706uk(C2749vk c2749vk, int i) {
        this.a = i;
        this.b = c2749vk;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.a();
                break;
            case 1:
                C2749vk c2749vk = this.b;
                c2749vk.c.execute(new RunnableC2706uk(c2749vk, 2));
                break;
            default:
                this.b.a();
                break;
        }
    }
}
