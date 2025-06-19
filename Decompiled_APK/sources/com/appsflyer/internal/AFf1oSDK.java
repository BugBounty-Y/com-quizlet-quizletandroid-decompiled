package com.appsflyer.internal;

import androidx.annotation.NonNull;
import com.appsflyer.AFLogger;
import com.appsflyer.internal.AFe1lSDK.AnonymousClass5;

/* loaded from: classes.dex */
public final class AFf1oSDK implements AFe1qSDK {
    private final Object AFAdRevenueData = new Object();
    private AFf1nSDK areAllFieldsValid;
    private AFi1vSDK component1;
    private final AFd1oSDK component2;
    private final AFf1iSDK component3;
    private final AFe1lSDK component4;
    private final AFf1gSDK getCurrencyIso4217Code;
    public final AFf1lSDK getMediationNetwork;
    private final AFc1pSDK getMonetizationNetwork;
    private final AFf1pSDK getRevenue;

    public AFf1oSDK(AFf1pSDK aFf1pSDK, AFc1pSDK aFc1pSDK, AFf1gSDK aFf1gSDK, AFf1lSDK aFf1lSDK, AFd1oSDK aFd1oSDK, AFf1iSDK aFf1iSDK, AFe1lSDK aFe1lSDK) {
        this.getRevenue = aFf1pSDK;
        this.getMonetizationNetwork = aFc1pSDK;
        this.getCurrencyIso4217Code = aFf1gSDK;
        this.getMediationNetwork = aFf1lSDK;
        this.component2 = aFd1oSDK;
        this.component3 = aFf1iSDK;
        this.component4 = aFe1lSDK;
        aFe1lSDK.AFAdRevenueData.add(this);
    }

    private void getMediationNetwork(@NonNull AFf1nSDK aFf1nSDK, AFf1mSDK aFf1mSDK) {
        synchronized (this.AFAdRevenueData) {
            this.areAllFieldsValid = aFf1nSDK;
        }
        if (aFf1mSDK != null) {
            aFf1mSDK.onRemoteConfigUpdateFinished(aFf1nSDK);
        }
    }

    public final AFi1vSDK AFAdRevenueData() {
        AFi1vSDK aFi1vSDK;
        synchronized (this.AFAdRevenueData) {
            aFi1vSDK = this.component1;
            this.component1 = null;
        }
        return aFi1vSDK;
    }

    public final void getCurrencyIso4217Code(AFf1mSDK aFf1mSDK) {
        AFf1qSDK aFf1qSDK = new AFf1qSDK(this.getRevenue, this.getMonetizationNetwork, this.getCurrencyIso4217Code, this.getMediationNetwork, this.component2, this.component3, "v1", aFf1mSDK);
        AFe1lSDK aFe1lSDK = this.component4;
        aFe1lSDK.getRevenue.execute(aFe1lSDK.new AnonymousClass5(aFf1qSDK));
    }

    @Override // com.appsflyer.internal.AFe1qSDK
    public final void getMonetizationNetwork(AFe1sSDK<?> aFe1sSDK) {
    }

    @Override // com.appsflyer.internal.AFe1qSDK
    public final void getCurrencyIso4217Code(AFe1sSDK<?> aFe1sSDK, AFe1rSDK aFe1rSDK) {
        if (aFe1sSDK instanceof AFf1qSDK) {
            AFf1qSDK aFf1qSDK = (AFf1qSDK) aFe1sSDK;
            AFf1nSDK aFf1nSDK = aFf1qSDK.component1;
            if (aFf1nSDK == null) {
                AFLogger.INSTANCE.w(AFg1cSDK.REMOTE_CONTROL, "update RC returned null result, something went wrong!");
                aFf1nSDK = AFf1nSDK.FAILURE;
            }
            if (aFf1nSDK != AFf1nSDK.USE_CACHED) {
                AFi1vSDK aFi1vSDK = aFf1qSDK.component3;
                synchronized (this.AFAdRevenueData) {
                    this.component1 = aFi1vSDK;
                }
            }
            getMediationNetwork(aFf1nSDK, aFf1qSDK.areAllFieldsValid);
        }
    }

    @Override // com.appsflyer.internal.AFe1qSDK
    public final void getMediationNetwork(AFe1sSDK<?> aFe1sSDK) {
        if (aFe1sSDK instanceof AFf1qSDK) {
            AFf1qSDK aFf1qSDK = (AFf1qSDK) aFe1sSDK;
            synchronized (this.AFAdRevenueData) {
                this.component1 = null;
            }
            getMediationNetwork(AFf1nSDK.FAILURE, aFf1qSDK.areAllFieldsValid);
        }
    }
}
