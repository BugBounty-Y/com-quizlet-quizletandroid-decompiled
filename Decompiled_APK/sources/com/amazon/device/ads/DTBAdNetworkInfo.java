package com.amazon.device.ads;

import java.util.HashMap;

/* loaded from: classes.dex */
public class DTBAdNetworkInfo {
    private static final String LOGTAG = "DTBAdNetworkInfo";
    private final String adNetworkName;
    private final HashMap<String, String> adNetworkProperties;

    public DTBAdNetworkInfo(DTBAdNetwork dTBAdNetwork) {
        this.adNetworkName = dTBAdNetwork != null ? dTBAdNetwork.toString() : DTBAdNetwork.UNKNOWN.toString();
        this.adNetworkProperties = new HashMap<>();
    }

    public String getAdNetworkName() {
        return this.adNetworkName;
    }

    public String getAdNetworkProperties(String str) {
        if (this.adNetworkProperties.containsKey(str)) {
            return this.adNetworkProperties.get(str);
        }
        DtbLog.error(LOGTAG, "DTB Ad NetworkProperties not found");
        return null;
    }

    public DTBAdNetworkInfo setAdNetworkProperties(String str, String str2) {
        this.adNetworkProperties.put(str, str2);
        return this;
    }

    public DTBAdNetworkInfo(com.amazon.aps.ads.model.b bVar) {
        String string;
        if (bVar != null) {
            string = bVar.toString();
        } else {
            string = "UNKNOWN";
        }
        this.adNetworkName = string;
        this.adNetworkProperties = new HashMap<>();
    }
}
