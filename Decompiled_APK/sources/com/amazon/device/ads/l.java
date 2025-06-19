package com.amazon.device.ads;

import android.content.Context;
import com.amazon.device.ads.DtbMetrics;

/* loaded from: classes.dex */
public final /* synthetic */ class l implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ l(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                ((DtbMetrics.Submitter) this.b).lambda$submitMetrics$0();
                break;
            case 1:
                ((DTBInterstitialActivity) this.b).lambda$useCustomButtonUpdated$0();
                break;
            case 2:
                ((DTBMetricsConfiguration) this.b).lambda$loadMobileClientConfig$0();
                break;
            case 3:
                ((DTBMetricsProcessor) this.b).lambda$dispenseReport$1();
                break;
            default:
                DtbOmSdkSessionManager.lambda$activateOMSDK$1((Context) this.b);
                break;
        }
    }
}
