package com.appsflyer.internal;

import androidx.annotation.NonNull;
import com.appsflyer.internal.components.network.http.ResponseNetwork;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* loaded from: classes.dex */
public class AFd1aSDK<Body> implements ResponseNetwork<Body> {
    final boolean AFAdRevenueData;

    @NonNull
    final Map<String, List<String>> getCurrencyIso4217Code;
    final int getMediationNetwork;

    @NonNull
    private final Body getMonetizationNetwork;

    @NonNull
    public final AFd1hSDK getRevenue;

    public AFd1aSDK(@NonNull Body body, int i, boolean z, Map<String, List<String>> map, @NonNull AFd1hSDK aFd1hSDK) {
        this.getMonetizationNetwork = body;
        this.getMediationNetwork = i;
        this.AFAdRevenueData = z;
        this.getCurrencyIso4217Code = new HashMap(map);
        this.getRevenue = aFd1hSDK;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        AFd1aSDK aFd1aSDK = (AFd1aSDK) obj;
        if (this.getMediationNetwork == aFd1aSDK.getMediationNetwork && this.AFAdRevenueData == aFd1aSDK.AFAdRevenueData && this.getMonetizationNetwork.equals(aFd1aSDK.getMonetizationNetwork) && this.getCurrencyIso4217Code.equals(aFd1aSDK.getCurrencyIso4217Code)) {
            return this.getRevenue.equals(aFd1aSDK.getRevenue);
        }
        return false;
    }

    @Override // com.appsflyer.internal.components.network.http.ResponseNetwork
    @NonNull
    public Body getBody() {
        return this.getMonetizationNetwork;
    }

    public final String getCurrencyIso4217Code(@NonNull String str) {
        List<String> headerField = getHeaderField(str);
        if (headerField == null || headerField.isEmpty()) {
            return null;
        }
        Iterator<String> it2 = headerField.iterator();
        StringBuilder sb = new StringBuilder(it2.next());
        while (it2.hasNext()) {
            sb.append(", ");
            sb.append(it2.next());
        }
        return sb.toString();
    }

    @Override // com.appsflyer.internal.components.network.http.ResponseNetwork
    public List<String> getHeaderField(@NonNull String str) {
        for (String str2 : this.getCurrencyIso4217Code.keySet()) {
            if (str2 != null && str2.equalsIgnoreCase(str)) {
                return this.getCurrencyIso4217Code.get(str2);
            }
        }
        return null;
    }

    @Override // com.appsflyer.internal.components.network.http.ResponseNetwork
    public int getStatusCode() {
        return this.getMediationNetwork;
    }

    public int hashCode() {
        return this.getRevenue.hashCode() + ((this.getCurrencyIso4217Code.hashCode() + (((((this.getMonetizationNetwork.hashCode() * 31) + this.getMediationNetwork) * 31) + (this.AFAdRevenueData ? 1 : 0)) * 31)) * 31);
    }

    @Override // com.appsflyer.internal.components.network.http.ResponseNetwork
    public boolean isSuccessful() {
        return this.AFAdRevenueData;
    }
}
