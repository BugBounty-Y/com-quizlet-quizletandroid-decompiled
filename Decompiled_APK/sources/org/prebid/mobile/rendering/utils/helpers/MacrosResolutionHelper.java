package org.prebid.mobile.rendering.utils.helpers;

import java.util.HashMap;
import java.util.Map;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.rendering.models.internal.MacrosModel;

/* loaded from: classes3.dex */
public abstract class MacrosResolutionHelper {
    public static String a(HashMap map, String str) {
        if (map.isEmpty()) {
            LogUtil.b("MacrosResolutionHelper", "resolveAuctionMacros: Failed. Macros map is null or empty.");
            return str;
        }
        for (Map.Entry entry : map.entrySet()) {
            String str2 = (String) entry.getKey();
            String str3 = ((MacrosModel) entry.getValue()).a;
            if (str3 == null) {
                str3 = "\\\\\"\\\\\"";
            }
            if (str == null || str.isEmpty()) {
                LogUtil.b("MacrosResolutionHelper", "replace: Failed. Input string is null or empty.");
                str = "";
            } else {
                str = str.replaceAll(str2, str3);
            }
        }
        return str;
    }
}
