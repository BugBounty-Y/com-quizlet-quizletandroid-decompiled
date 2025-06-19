package com.pubmatic.sdk.openwrap.core.internal;

import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.base.c;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.models.a;
import com.pubmatic.sdk.common.utility.o;
import com.pubmatic.sdk.openwrap.core.f;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class a implements com.pubmatic.sdk.common.base.b {
    private String a;
    private String b;
    private int c;
    private int d;
    private String e;
    private com.pubmatic.sdk.common.base.a f;

    @Override // com.pubmatic.sdk.common.base.b
    public void build(@NonNull com.pubmatic.sdk.common.models.a aVar) throws JSONException, NumberFormatException {
        if (this.f == null) {
            POBLog.error("POBBidsBuilder", "Listener is null, execution of Wrapper ad builder gets break.", new Object[0]);
            return;
        }
        a.C0010a c0010a = new a.C0010a(aVar);
        JSONObject customData = aVar.getCustomData();
        if (customData != null) {
            try {
                c0010a.setSendAllBidsState(customData.getJSONObject("ext").optInt("sendallbids") != 0);
            } catch (JSONException unused) {
                POBLog.error("POBBidsBuilder", "Unable to fetch logger and tracker details", new Object[0]);
            }
            List<c> bids = aVar.getBids();
            JSONArray jSONArrayOptJSONArray = customData.optJSONArray("seatbid");
            if (jSONArrayOptJSONArray != null && jSONArrayOptJSONArray.length() > 0) {
                for (int i = 0; i < jSONArrayOptJSONArray.length(); i++) {
                    JSONObject jSONObjectOptJSONObject = jSONArrayOptJSONArray.optJSONObject(i);
                    if (jSONObjectOptJSONObject != null) {
                        JSONArray jSONArrayOptJSONArray2 = jSONObjectOptJSONObject.optJSONArray("bid");
                        String strOptString = jSONObjectOptJSONObject.optString("seat");
                        if (strOptString.isEmpty()) {
                            strOptString = this.a;
                        }
                        if (jSONArrayOptJSONArray2 != null) {
                            for (int i2 = 0; i2 < jSONArrayOptJSONArray2.length(); i2++) {
                                f fVarBuild = f.build(strOptString, jSONArrayOptJSONArray2.optJSONObject(i2));
                                if (o.isNullOrEmpty(fVarBuild.getId())) {
                                    POBLog.warn("POBBidsBuilder", "Bid id is invalid and hence ignoring this OW bid.", new Object[0]);
                                } else {
                                    f.a aVar2 = new f.a(fVarBuild);
                                    if (o.isNullOrEmpty(fVarBuild.getCreativeType())) {
                                        aVar2.setCreativeType(this.e);
                                    }
                                    if (o.isNullOrEmpty(fVarBuild.getPartnerId())) {
                                        aVar2.setPartnerId(this.b);
                                    }
                                    if (fVarBuild.getWidth() == 0) {
                                        aVar2.setWidth(this.c);
                                    }
                                    if (fVarBuild.getHeight() == 0) {
                                        aVar2.setHeight(this.d);
                                    }
                                    bids.add(aVar2.build());
                                }
                            }
                        }
                    }
                }
            }
            if (bids.size() > 0) {
                c0010a.setRefreshInterval(((f) bids.get(0)).getRefreshInterval());
            }
            this.f.adBuilderOnSuccess(c0010a.build());
        }
    }

    public String getPartnerId() {
        return this.b;
    }

    public void setCreativeType(String str) {
        this.e = str;
    }

    public void setHeight(int i) {
        this.d = i;
    }

    @Override // com.pubmatic.sdk.common.base.b
    public void setListener(com.pubmatic.sdk.common.base.a aVar) {
        this.f = aVar;
    }

    public void setPartnerId(String str) {
        this.b = str;
    }

    public void setPartnerName(String str) {
        this.a = str;
    }

    public void setWidth(int i) {
        this.c = i;
    }
}
