package com.appsflyer.internal;

import androidx.annotation.NonNull;
import com.appsflyer.attribution.AppsFlyerRequestListener;
import com.appsflyer.internal.components.network.http.ResponseNetwork;
import com.appsflyer.internal.components.network.http.exceptions.ParsingException;
import com.appsflyer.share.LinkGenerator;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/* loaded from: classes.dex */
public final class AFe1kSDK extends AFe1dSDK<String> {
    private final String component2;
    private final Map<String, String> copy;
    private final LinkGenerator.ResponseListener copydefault;

    @NonNull
    private final LinkGenerator equals;

    @NonNull
    private final UUID hashCode;
    private final String toString;

    public AFe1kSDK(@NonNull AFc1dSDK aFc1dSDK, @NonNull UUID uuid, @NonNull String str, @NonNull Map<String, String> map, String str2, LinkGenerator.ResponseListener responseListener, @NonNull LinkGenerator linkGenerator) {
        super(AFe1mSDK.ONELINK, new AFe1mSDK[]{AFe1mSDK.RC_CDN}, aFc1dSDK, uuid.toString());
        this.hashCode = uuid;
        this.component2 = str;
        this.copy = new HashMap(map);
        this.copydefault = responseListener;
        this.toString = str2;
        this.equals = linkGenerator;
    }

    @Override // com.appsflyer.internal.AFe1dSDK
    public final boolean a_() {
        return false;
    }

    @Override // com.appsflyer.internal.AFe1dSDK
    public final AppsFlyerRequestListener component3() {
        return null;
    }

    @Override // com.appsflyer.internal.AFe1dSDK
    public final boolean copydefault() {
        return false;
    }

    @Override // com.appsflyer.internal.AFe1dSDK, com.appsflyer.internal.AFe1sSDK
    public final long getMonetizationNetwork() {
        return 3000L;
    }

    @Override // com.appsflyer.internal.AFe1dSDK, com.appsflyer.internal.AFe1sSDK
    public final void getRevenue() {
        ResponseNetwork responseNetwork;
        super.getRevenue();
        LinkGenerator.ResponseListener responseListener = this.copydefault;
        if (responseListener != null) {
            if (this.getMediationNetwork == AFe1rSDK.SUCCESS && (responseNetwork = ((AFe1dSDK) this).component1) != null) {
                responseListener.onResponse((String) responseNetwork.getBody());
                return;
            }
            Throwable thComponent4 = component4();
            if (!(thComponent4 instanceof ParsingException)) {
                responseListener.onResponse(this.equals.generateLink());
            } else if (((ParsingException) thComponent4).getRawResponse().isSuccessful()) {
                responseListener.onResponseError("Can't parse one link data");
            } else {
                responseListener.onResponse(this.equals.generateLink());
            }
        }
    }

    @Override // com.appsflyer.internal.AFe1dSDK
    public final AFd1nSDK<String> getRevenue(@NonNull String str) {
        return this.component4.getMonetizationNetwork(this.component2, this.copy, this.toString, this.hashCode, str);
    }
}
