package com.amazon.device.ads;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.DisplayMetrics;
import android.view.WindowManager;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes.dex */
public class DTBAdInterstitial {
    protected static final String INTERSTITIAL_CACHE_KEY = "INTERSTITIAL_CACHE_KEY";
    private static final String LOG_TAG = "DTBAdInterstitial";
    private static Map<Integer, DTBAdInterstitial> dtbAdInterstitialCache = Collections.synchronizedMap(new HashMap());
    DTBAdView adView;
    private Context context;

    public DTBAdInterstitial(Context context, DTBAdInterstitialListener dTBAdInterstitialListener) {
        try {
            this.context = context;
            this.adView = new DTBAdView(context, dTBAdInterstitialListener);
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, "Fail to initialize DTBAdInterstitial class", e);
        }
    }

    public static DTBAdInterstitial getFromCache(int i) {
        if (dtbAdInterstitialCache.containsKey(Integer.valueOf(i))) {
            return dtbAdInterstitialCache.get(Integer.valueOf(i));
        }
        return null;
    }

    private DTBAdMRAIDInterstitialController getInterstitialController() {
        return (DTBAdMRAIDInterstitialController) this.adView.getController();
    }

    private DTBAdInterstitialListener getInterstitialListener() {
        return getInterstitialController().getInterstitialListener();
    }

    public static int getWidth(Context context) {
        try {
            DisplayMetrics displayMetrics = new DisplayMetrics();
            ((WindowManager) context.getSystemService("window")).getDefaultDisplay().getMetrics(displayMetrics);
            return displayMetrics.widthPixels;
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute getWidth method", e);
            return 0;
        }
    }

    private static int putInCache(DTBAdInterstitial dTBAdInterstitial) {
        dtbAdInterstitialCache.put(Integer.valueOf(dTBAdInterstitial.hashCode()), dTBAdInterstitial);
        return dTBAdInterstitial.hashCode();
    }

    public static void removeFromCache(int i) {
        dtbAdInterstitialCache.remove(Integer.valueOf(i));
    }

    public void fetchAd(Map<String, Object> map) {
        this.adView.fetchAd((Map<String, ? extends Object>) map);
    }

    public DTBAdView getAdView() {
        return this.adView;
    }

    public void onAdClosed() {
        DTBAdInterstitialListener interstitialListener = getInterstitialListener();
        if (interstitialListener != null) {
            interstitialListener.onAdClosed(this.adView);
        }
    }

    public void setDtbAdInterstitialListener(DTBAdInterstitialListener dTBAdInterstitialListener) {
        try {
            this.adView = new DTBAdView(this.context, dTBAdInterstitialListener);
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, "Fail to initialize DTBAdInterstitial class", e);
        }
    }

    public void setListener(DTBAdInterstitialListener dTBAdInterstitialListener) {
        getInterstitialController().setInterstitialListener(dTBAdInterstitialListener);
    }

    public void show() {
        try {
            if (getInterstitialController() == null) {
                com.amazon.aps.shared.a.e(1, 1, "There is no controller before showing the interstitial ad", null);
                return;
            }
            Intent intent = new Intent(this.context, (Class<?>) DTBInterstitialActivity.class);
            intent.putExtra(INTERSTITIAL_CACHE_KEY, putInCache(this));
            getInterstitialController().startOMSDKSession();
            this.context.startActivity(intent);
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, "Fail to execute show method", e);
        }
    }

    public void fetchAd(Bundle bundle) {
        try {
            this.adView.fetchAd(bundle.getString("bid_html_template", ""), bundle);
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, "Fail to execute fetchAd method with extraData argument", e);
        }
    }

    public void fetchAd(String str) {
        try {
            this.adView.fetchAd(str);
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, "Fail to execute fetchAd method with adHtml argument", e);
        }
    }

    public DTBAdInterstitial(Context context) {
        this.context = context;
    }

    public void fetchAd(String str, Bundle bundle) {
        try {
            this.adView.fetchAd(str, bundle);
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, "Fail to execute fetchAd method with adHtml and  bundle argument", e);
        }
    }
}
