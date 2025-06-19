package org.prebid.mobile.rendering.models.openrtb.bidRequests;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes3.dex */
public class PluginRendererList extends BaseBid {
    public ArrayList a;

    public final void a(JSONObject jSONObject, List list) throws JSONException {
        JSONArray jSONArray = new JSONArray();
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            PluginRenderer pluginRenderer = (PluginRenderer) it2.next();
            JSONObject jSONObject2 = new JSONObject();
            jSONObject2.put("name", pluginRenderer.a);
            jSONObject2.put("version", pluginRenderer.b);
            jSONArray.put(jSONObject2);
        }
        jSONObject.put("renderers", jSONArray);
    }
}
