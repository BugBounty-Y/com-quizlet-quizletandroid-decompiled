package com.amazon.device.ads;

/* loaded from: classes.dex */
public final /* synthetic */ class h implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ DTBAdMRAIDController b;

    public /* synthetic */ h(DTBAdMRAIDController dTBAdMRAIDController, int i) {
        this.a = i;
        this.b = dTBAdMRAIDController;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.lambda$onMRAIDUnload$2();
                break;
            default:
                this.b.lambda$setState$1();
                break;
        }
    }
}
