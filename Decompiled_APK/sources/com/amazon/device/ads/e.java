package com.amazon.device.ads;

/* loaded from: classes.dex */
public final /* synthetic */ class e implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ DTBAdMRAIDBannerController b;
    public final /* synthetic */ int c;
    public final /* synthetic */ boolean d;

    public /* synthetic */ e(DTBAdMRAIDBannerController dTBAdMRAIDBannerController, int i, boolean z, int i2) {
        this.a = i2;
        this.b = dTBAdMRAIDBannerController;
        this.c = i;
        this.d = z;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.lambda$moveResizedToDefault$0(this.c, this.d);
                break;
            default:
                this.b.lambda$moveExpandedToDefault$2(this.c, this.d);
                break;
        }
    }
}
