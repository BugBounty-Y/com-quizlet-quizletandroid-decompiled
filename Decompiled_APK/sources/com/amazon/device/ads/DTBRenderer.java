package com.amazon.device.ads;

import android.app.Activity;
import android.view.View;
import java.util.List;

/* loaded from: classes.dex */
public class DTBRenderer {
    private static final String LOG_TAG = "DTBRenderer";
    Activity activity;
    String adUnitId;
    protected DTBAdResponse dtbAdResponse;
    protected boolean showOnLoad = false;

    public DTBRenderer(String str, Activity activity, DTBAdResponse dTBAdResponse) {
        this.adUnitId = str;
        this.dtbAdResponse = dTBAdResponse;
        this.activity = activity;
    }

    public EventDistributor getEventDistributer() {
        return AdRegistration.getEventDistributer();
    }

    public DTBAdSize getSize() {
        try {
            DTBAdResponse dTBAdResponse = this.dtbAdResponse;
            if (dTBAdResponse == null) {
                return null;
            }
            List<DTBAdSize> dTBAds = dTBAdResponse.getDTBAds();
            if (dTBAds.size() > 0) {
                return dTBAds.get(0);
            }
            return null;
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(2, 1, "Fail to execute getSize method", e);
            return null;
        }
    }

    public boolean isShowOnLoad() {
        return this.showOnLoad;
    }

    public void onCustomBannerFailure(View view) {
    }

    public void onCustomBannerSuccess(View view) {
    }
}
