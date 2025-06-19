package org.prebid.mobile.rendering.models.openrtb.bidRequests;

import java.io.Serializable;
import java.util.HashMap;
import org.json.JSONObject;

/* loaded from: classes3.dex */
public class Ext implements Serializable {
    public final HashMap a = new HashMap();

    public final JSONObject a() {
        return new JSONObject(this.a);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        HashMap map = this.a;
        HashMap map2 = ((Ext) obj).a;
        return map != null ? map.equals(map2) : map2 == null;
    }

    public final int hashCode() {
        HashMap map = this.a;
        if (map != null) {
            return map.hashCode();
        }
        return 0;
    }
}
