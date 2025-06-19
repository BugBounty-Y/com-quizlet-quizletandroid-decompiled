package com.amazon.device.ads;

/* loaded from: classes.dex */
public final /* synthetic */ class b implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ DTBAdMRAIDBannerController b;

    public /* synthetic */ b(DTBAdMRAIDBannerController dTBAdMRAIDBannerController, int i) {
        this.a = i;
        this.b = dTBAdMRAIDBannerController;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.lambda$passLoadError$18();
                break;
            case 1:
                this.b.lambda$onAdLoaded$16();
                break;
            case 2:
                this.b.lambda$onMRAIDUnload$4();
                break;
            case 3:
                this.b.lambda$onAdLeftApplication$15();
                break;
            case 4:
                this.b.lambda$onAdFailedToLoad$17();
                break;
            case 5:
                this.b.lambda$updateExpandedToDefaultListener$11();
                break;
            case 6:
                this.b.lambda$updateExpandedToDefaultListener$12();
                break;
            case 7:
                this.b.lambda$updateResizedToDefaultListener$9();
                break;
            case 8:
                this.b.lambda$updateResizedToDefaultListener$10();
                break;
            case 9:
                this.b.lambda$useCustomButtonUpdated$13();
                break;
            default:
                this.b.lambda$impressionFired$19();
                break;
        }
    }
}
