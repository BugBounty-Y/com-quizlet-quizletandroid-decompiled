package com.appsflyer.internal;

/* loaded from: classes.dex */
public final /* synthetic */ class l implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ AFj1nSDK b;

    public /* synthetic */ l(AFj1nSDK aFj1nSDK, int i) {
        this.a = i;
        this.b = aFj1nSDK;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.areAllFieldsValid();
                break;
            case 1:
                this.b.component1();
                break;
            default:
                this.b.component4();
                break;
        }
    }
}
