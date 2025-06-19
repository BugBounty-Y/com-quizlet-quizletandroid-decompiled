package com.appsflyer.internal;

import com.appsflyer.AFLogger;
import com.onetrust.otpublishers.headless.Public.OTCCPAGeolocationConstants;
import java.util.ArrayList;
import java.util.Locale;
import java.util.regex.Pattern;

/* loaded from: classes.dex */
public final class AFb1uSDK {
    public final String[] getMediationNetwork;

    public AFb1uSDK(String... strArr) {
        if (strArr == null || strArr.length == 0) {
            this.getMediationNetwork = null;
            return;
        }
        Pattern patternCompile = Pattern.compile("[\\w]{1,45}");
        ArrayList arrayList = new ArrayList();
        for (String str : strArr) {
            if (str == null || !patternCompile.matcher(str).matches()) {
                AFLogger.afWarnLog("Invalid partner name: ".concat(String.valueOf(str)));
            } else {
                arrayList.add(str.toLowerCase(Locale.getDefault()));
            }
        }
        if (arrayList.contains(OTCCPAGeolocationConstants.ALL)) {
            this.getMediationNetwork = new String[]{OTCCPAGeolocationConstants.ALL};
        } else if (arrayList.isEmpty()) {
            this.getMediationNetwork = null;
        } else {
            this.getMediationNetwork = (String[]) arrayList.toArray(new String[0]);
        }
    }
}
