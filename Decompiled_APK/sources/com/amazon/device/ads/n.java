package com.amazon.device.ads;

/* loaded from: classes.dex */
public final /* synthetic */ class n implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ DtbOmSdkSessionManager b;

    public /* synthetic */ n(DtbOmSdkSessionManager dtbOmSdkSessionManager, int i) {
        this.a = i;
        this.b = dtbOmSdkSessionManager;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.lambda$displayAdEventLoaded$5();
                break;
            case 1:
                this.b.lambda$new$0();
                break;
            case 2:
                this.b.lambda$startAdSession$4();
                break;
            case 3:
                this.b.lambda$stopOmAdSession$7();
                break;
            default:
                this.b.lambda$impressionOccured$6();
                break;
        }
    }
}
