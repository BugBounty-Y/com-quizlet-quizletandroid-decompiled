package com.amazon.device.ads;

import android.content.Context;

/* loaded from: classes.dex */
public class DTBAdView extends com.amazon.aps.ads.util.adview.e {
    static final String LOG_TAG = "DTBAdView";

    public DTBAdView(Context context) {
        super(context);
    }

    public DTBAdMRAIDController getController() {
        return getMraidHandler();
    }

    public void initAdBannerListener(DTBAdBannerListener dTBAdBannerListener) {
        try {
            setMraidListenerAdapter(new com.amazon.aps.ads.metrics.b(getBidId(), dTBAdBannerListener));
            setMraidHandler(new DTBAdMRAIDBannerController(this, (com.amazon.aps.ads.metrics.b) getMraidListenerAdapter()));
            initWebView();
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, "Fail to initialize DTBAdView class with DTBAdBannerListener", e);
        }
    }

    public void initAdExpandedListener(DTBAdExpandedListener dTBAdExpandedListener, int i) {
        try {
            DTBAdMRAIDExpandedController dTBAdMRAIDExpandedController = new DTBAdMRAIDExpandedController(this);
            setMraidHandler(dTBAdMRAIDExpandedController);
            dTBAdMRAIDExpandedController.setMasterController(DTBAdMRAIDBannerController.findControllerByIndex(i));
            dTBAdExpandedListener.onCreateExpandedController((DTBAdMRAIDExpandedController) getMraidHandler());
            initWebView();
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, "Fail to initialize DTBAdView class with DTBAdExpandedListener", e);
        }
    }

    public void initAdInterstitialListener(DTBAdInterstitialListener dTBAdInterstitialListener) {
        try {
            setMraidListenerAdapter(new com.amazon.aps.ads.metrics.c(getBidId(), dTBAdInterstitialListener));
            setMraidHandler(new DTBAdMRAIDInterstitialController(this, (com.amazon.aps.ads.metrics.c) getMraidListenerAdapter()));
            initWebView();
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, "Fail to initialize DTBAdView class with DTBAdInterstitialListener", e);
        }
    }

    public DTBAdView(Context context, DTBAdInterstitialListener dTBAdInterstitialListener) {
        super(context);
        initAdInterstitialListener(dTBAdInterstitialListener);
    }

    public DTBAdView(Context context, DTBAdBannerListener dTBAdBannerListener) {
        super(context);
        initAdBannerListener(dTBAdBannerListener);
    }

    public DTBAdView(Context context, DTBAdExpandedListener dTBAdExpandedListener) {
        this(context, dTBAdExpandedListener, 0);
    }

    public DTBAdView(Context context, DTBAdExpandedListener dTBAdExpandedListener, int i) {
        super(context);
        initAdExpandedListener(dTBAdExpandedListener, i);
    }
}
