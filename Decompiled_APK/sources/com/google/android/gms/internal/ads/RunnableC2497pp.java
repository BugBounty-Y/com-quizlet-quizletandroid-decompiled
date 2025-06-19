package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.pp, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC2497pp implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ BinderC2625sp b;

    public /* synthetic */ RunnableC2497pp(BinderC2625sp binderC2625sp, int i) {
        this.a = i;
        this.b = binderC2625sp;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.e4(5);
                break;
            default:
                BinderC2625sp binderC2625sp = this.b;
                binderC2625sp.a.a().execute(new RunnableC2497pp(binderC2625sp, 0));
                break;
        }
    }
}
