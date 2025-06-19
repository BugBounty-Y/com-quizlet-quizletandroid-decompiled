package com.amazon.device.ads;

/* loaded from: classes.dex */
public final /* synthetic */ class j implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ DTBAdRequest b;

    public /* synthetic */ j(DTBAdRequest dTBAdRequest, int i) {
        this.a = i;
        this.b = dTBAdRequest;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.lambda$new$0();
                break;
            default:
                this.b.lambda$internalLoadAd$1();
                break;
        }
    }
}
