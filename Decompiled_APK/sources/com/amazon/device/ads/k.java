package com.amazon.device.ads;

import android.view.View;
import android.webkit.WebView;
import java.util.List;
import java.util.Map;

/* loaded from: classes.dex */
public final /* synthetic */ class k implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ k(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                ((DTBAdRequest) this.b).lambda$triggerCallBack$2((DtbMetrics) this.c);
                break;
            case 1:
                ((DTBAdMRAIDBannerController) this.b).lambda$expand$7((Map) this.c);
                break;
            case 2:
                ((DTBAdMRAIDBannerController) this.b).lambda$onAdClicked$14((View) this.c);
                break;
            case 3:
                ((DTBAdMRAIDController) this.b).lambda$evaluateJavascript$0((String) this.c);
                break;
            case 4:
                ((DTBMetricsProcessor) this.b).lambda$submitExpiredReport$0((List) this.c);
                break;
            default:
                ((DtbOmSdkSessionManager) this.b).lambda$registerAdView$3((WebView) this.c);
                break;
        }
    }
}
