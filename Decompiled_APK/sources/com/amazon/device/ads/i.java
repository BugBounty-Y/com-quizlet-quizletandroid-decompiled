package com.amazon.device.ads;

/* loaded from: classes.dex */
public final /* synthetic */ class i implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ DTBAdMRAIDInterstitialController b;

    public /* synthetic */ i(DTBAdMRAIDInterstitialController dTBAdMRAIDInterstitialController, int i) {
        this.a = i;
        this.b = dTBAdMRAIDInterstitialController;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.lambda$onAdFailedToLoad$3();
                break;
            case 1:
                this.b.lambda$onAdClicked$1();
                break;
            case 2:
                this.b.lambda$onAdError$4();
                break;
            case 3:
                this.b.lambda$onAdLoaded$2();
                break;
            case 4:
                this.b.lambda$impressionFired$6();
                break;
            case 5:
                this.b.lambda$onAdLeftApplication$5();
                break;
            case 6:
                this.b.lambda$onVideoCompleted$7();
                break;
            default:
                this.b.lambda$executeClose$0();
                break;
        }
    }
}
