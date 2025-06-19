package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final /* synthetic */ class Qi implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Ui b;
    public final /* synthetic */ AbstractBinderC2814x5 c;

    /* JADX WARN: Multi-variable type inference failed */
    public /* synthetic */ Qi(Ui ui, InterfaceViewOnClickListenerC2705uj interfaceViewOnClickListenerC2705uj, int i) {
        this.a = i;
        switch (i) {
            case 1:
                this.b = ui;
                this.c = (AbstractBinderC2814x5) interfaceViewOnClickListenerC2705uj;
                break;
            default:
                this.b = ui;
                this.c = (AbstractBinderC2814x5) interfaceViewOnClickListenerC2705uj;
                break;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v1, types: [com.google.android.gms.internal.ads.uj, com.google.android.gms.internal.ads.x5] */
    /* JADX WARN: Type inference failed for: r0v2, types: [com.google.android.gms.internal.ads.uj, com.google.android.gms.internal.ads.x5] */
    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.o(this.c);
                break;
            default:
                this.b.q(this.c);
                break;
        }
    }
}
