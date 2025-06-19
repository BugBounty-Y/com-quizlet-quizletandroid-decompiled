package com.pubmatic.sdk.openwrap.core;

import androidx.annotation.NonNull;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.pubmatic.sdk.common.log.POBLog;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class f implements com.pubmatic.sdk.common.base.c {
    private int A;
    private String a;
    private String b;
    private double c;
    private int d;
    private int e;
    private String f;
    private String g;
    private String h;
    private String i;
    private String j;
    private String k;
    private int l;
    private int m;
    private List<b> n;
    private List<x> o;
    private Map<String, String> p;
    private JSONObject q;
    private String r;
    private String s;
    private boolean t;
    private long v;
    private boolean w;
    private boolean y;
    private String z;
    private final long u = System.currentTimeMillis();

    @NonNull
    private String x = com.pubmatic.sdk.common.base.c.DYNAMIC_PRICE_BID;

    public static class a {

        @NonNull
        private final f a;
        private String b;
        private String c;
        private int d;
        private int e;

        @NonNull
        private String f;
        private int g;

        public a(@NonNull f fVar) {
            this.a = fVar;
            this.b = fVar.s;
            this.c = fVar.g;
            this.d = fVar.l;
            this.e = fVar.m;
            this.f = fVar.x;
            this.g = fVar.d;
        }

        @NonNull
        public f build() {
            f fVar = this.a;
            f fVarCreate = f.create(fVar, fVar.p);
            fVarCreate.s = this.b;
            fVarCreate.g = this.c;
            fVarCreate.l = this.d;
            fVarCreate.m = this.e;
            fVarCreate.x = this.f;
            fVarCreate.d = this.g;
            return fVarCreate;
        }

        @NonNull
        public a setBidStatus(int i) {
            this.g = i;
            return this;
        }

        @NonNull
        public a setBidType(@NonNull String str) {
            this.f = str;
            return this;
        }

        @NonNull
        public a setCreativeType(@NonNull String str) {
            this.b = str;
            return this;
        }

        @NonNull
        public a setHeight(int i) {
            this.e = i;
            return this;
        }

        @NonNull
        public a setPartnerId(@NonNull String str) {
            this.c = str;
            return this;
        }

        @NonNull
        public a setWidth(int i) {
            this.d = i;
            return this;
        }
    }

    public static class b {
        private String a;
        private String b;
        private int c;
        private double d;
        private int e;
        private int f;

        public static b a(JSONObject jSONObject) {
            b bVar = new b();
            bVar.a = jSONObject.optString("bidder");
            int iOptInt = jSONObject.optInt("errorCode");
            String strOptString = jSONObject.optString("errorMessage");
            if (iOptInt > 0) {
                bVar.c = iOptInt;
                bVar.b = strOptString;
            }
            bVar.d = jSONObject.optDouble("bid");
            bVar.e = jSONObject.optInt(OTUXParamsKeys.OT_UX_WIDTH);
            bVar.f = jSONObject.optInt(OTUXParamsKeys.OT_UX_HEIGHT);
            return bVar;
        }

        public double getBidValue() {
            return this.d;
        }

        public String getBidderName() {
            return this.a;
        }

        public int getErrorCode() {
            return this.c;
        }

        public String getErrorMessage() {
            return this.b;
        }

        public int getHeight() {
            return this.f;
        }

        public int getWidth() {
            return this.e;
        }

        @NonNull
        public String toString() {
            return "Summary: BidderName[" + getBidderName() + "], BidValue[" + getBidValue() + "], Height[" + getHeight() + "], Width[" + getWidth() + "], ErrorMessage[" + getErrorMessage() + "], ErrorCode[" + getErrorCode() + "]";
        }
    }

    private f() {
    }

    @NonNull
    public static f build(@NonNull String str, @NonNull JSONObject jSONObject) throws JSONException, NumberFormatException {
        JSONObject jSONObjectOptJSONObject;
        JSONObject jSONObjectOptJSONObject2;
        JSONObject jSONObjectOptJSONObject3;
        JSONArray jSONArrayOptJSONArray;
        int i;
        List<x> list;
        f fVar = new f();
        fVar.q = jSONObject;
        fVar.a = jSONObject.optString("impid");
        fVar.b = jSONObject.optString("id");
        fVar.i = jSONObject.optString("adm");
        fVar.h = jSONObject.optString("crid");
        fVar.f = str;
        double dOptDouble = jSONObject.optDouble("price", 0.0d);
        fVar.c = dOptDouble;
        fVar.d = dOptDouble > 0.0d ? 1 : 0;
        String strOptString = jSONObject.optString("dealid");
        if (!com.pubmatic.sdk.common.utility.o.isNullOrEmpty(strOptString)) {
            fVar.j = strOptString;
        }
        fVar.k = jSONObject.optString("nurl");
        fVar.l = jSONObject.optInt("w");
        fVar.m = jSONObject.optInt("h");
        fVar.r = jSONObject.optString("lurl");
        fVar.z = jSONObject.optString("bundle", null);
        JSONObject jSONObjectOptJSONObject4 = jSONObject.optJSONObject("ext");
        if (jSONObjectOptJSONObject4 != null) {
            fVar.w = jSONObjectOptJSONObject4.optInt("winner") == 1;
            String strOptString2 = jSONObjectOptJSONObject4.optString("crtype");
            fVar.s = strOptString2;
            fVar.t = com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_VIDEO.equals(strOptString2);
            fVar.A = jSONObjectOptJSONObject4.optInt("dspid", 0);
            int iOptInt = jSONObjectOptJSONObject4.optInt("refreshInterval", 0);
            JSONObject jSONObjectOptJSONObject5 = fVar.t ? jSONObjectOptJSONObject4.optJSONObject(com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_VIDEO) : jSONObjectOptJSONObject4.optJSONObject(com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_BANNER);
            if (jSONObjectOptJSONObject5 != null && (jSONObjectOptJSONObject2 = jSONObjectOptJSONObject5.optJSONObject("clientconfig")) != null) {
                iOptInt = jSONObjectOptJSONObject2.optInt("refreshinterval", iOptInt);
                if (fVar.t && (jSONObjectOptJSONObject3 = jSONObjectOptJSONObject2.optJSONObject("reward")) != null && (jSONArrayOptJSONArray = jSONObjectOptJSONObject3.optJSONArray("rewards")) != null && jSONArrayOptJSONArray.length() > 0) {
                    fVar.o = new ArrayList(jSONArrayOptJSONArray.length());
                    for (int i2 = 0; i2 < jSONArrayOptJSONArray.length(); i2++) {
                        JSONObject jSONObjectOptJSONObject6 = jSONArrayOptJSONArray.optJSONObject(i2);
                        if (jSONObjectOptJSONObject6 != null && jSONObjectOptJSONObject6.has(DBUserFields.Names.USER_UPGRADE_TYPE) && jSONObjectOptJSONObject6.has("value")) {
                            String strOptString3 = jSONObjectOptJSONObject6.optString(DBUserFields.Names.USER_UPGRADE_TYPE, "");
                            try {
                                i = Integer.parseInt(jSONObjectOptJSONObject6.optString("value"));
                            } catch (NumberFormatException unused) {
                                POBLog.warn("POBBid", "Received invalid reward values", new Object[0]);
                                i = 0;
                            }
                            if (i > 0 && (list = fVar.o) != null) {
                                list.add(new x(strOptString3, i));
                            }
                        }
                    }
                }
            }
            fVar.e = com.pubmatic.sdk.common.utility.o.getValidRefreshInterval(iOptInt, 5);
            JSONArray jSONArrayOptJSONArray2 = jSONObjectOptJSONObject4.optJSONArray(OTUXParamsKeys.OT_UX_SUMMARY);
            if (jSONArrayOptJSONArray2 != null && jSONArrayOptJSONArray2.length() > 0) {
                fVar.n = new ArrayList(jSONArrayOptJSONArray2.length());
                for (int i3 = 0; i3 < jSONArrayOptJSONArray2.length(); i3++) {
                    try {
                        List<b> list2 = fVar.n;
                        if (list2 != null) {
                            list2.add(b.a(jSONArrayOptJSONArray2.getJSONObject(i3)));
                        }
                    } catch (JSONException e) {
                        POBLog.error("POBBid", "Exception on parsing summary object : " + e.getMessage(), new Object[0]);
                    }
                }
            }
            JSONObject jSONObjectOptJSONObject7 = jSONObjectOptJSONObject4.optJSONObject("prebid");
            if (jSONObjectOptJSONObject7 != null && (jSONObjectOptJSONObject = jSONObjectOptJSONObject7.optJSONObject("targeting")) != null) {
                try {
                    fVar.p = new HashMap(4);
                    Iterator<String> itKeys = jSONObjectOptJSONObject.keys();
                    while (itKeys.hasNext()) {
                        String next = itKeys.next();
                        String string = jSONObjectOptJSONObject.getString(next);
                        Map<String, String> map = fVar.p;
                        if (map != null) {
                            map.put(next, string);
                        }
                    }
                } catch (JSONException e2) {
                    POBLog.error("POBBid", "Exception on parsing prebid object : " + e2.getMessage(), new Object[0]);
                }
            }
        }
        return fVar;
    }

    @NonNull
    public static f create(@NonNull f fVar, Map<String, String> map) {
        f fVar2 = new f();
        a(fVar2, fVar);
        Map<String, String> map2 = fVar.p;
        if (map2 == null || map2.isEmpty()) {
            fVar2.p = map;
            return fVar2;
        }
        fVar2.p = fVar.p;
        return fVar2;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public com.pubmatic.sdk.common.base.c buildWithRefreshAndExpiryTimeout(int i, int i2) {
        f fVarCreate = create(this, this.p);
        fVarCreate.e = i;
        fVarCreate.v = i2;
        return fVarCreate;
    }

    public boolean equals(Object obj) {
        String str;
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f) || (str = this.b) == null) {
            return false;
        }
        return str.equals(((f) obj).getId());
    }

    public List<x> getAllRewards() {
        return this.o;
    }

    @NonNull
    public String getBidType() {
        return this.x;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public String getBundle() {
        return this.z;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public int getContentHeight() {
        return this.m;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public int getContentWidth() {
        return this.l;
    }

    public String getCreative() {
        return this.i;
    }

    public String getCreativeId() {
        return this.h;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public String getCreativeType() {
        return this.s;
    }

    public String getDealId() {
        return this.j;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public int getDspId() {
        return this.A;
    }

    public x getFirstReward() {
        List<x> list = this.o;
        if (list == null || list.isEmpty()) {
            return null;
        }
        return this.o.get(0);
    }

    @Deprecated
    public double getGrossPrice() {
        return this.c;
    }

    public int getHeight() {
        return this.m;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public String getId() {
        return this.b;
    }

    public String getImpressionId() {
        return this.a;
    }

    public String getPartnerId() {
        return this.g;
    }

    public String getPartnerName() {
        return this.f;
    }

    public double getPrice() {
        return this.c;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public JSONObject getRawBid() {
        return this.q;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public int getRefreshInterval() {
        return this.e;
    }

    public int getRemainingExpirationTime() {
        return (int) (this.v - (System.currentTimeMillis() - this.u));
    }

    @Override // com.pubmatic.sdk.common.base.c
    public String getRenderableContent() {
        return this.i;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public int getStatus() {
        return this.d;
    }

    @Deprecated
    public List<b> getSummary() {
        return this.n;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public Map<String, String> getTargetingInfo() {
        if (this.d == 1) {
            return this.p;
        }
        return null;
    }

    public int getWidth() {
        return this.l;
    }

    public String getlURL() {
        return this.r;
    }

    public String getnURL() {
        return this.k;
    }

    public boolean hasWon() {
        return this.y;
    }

    public int hashCode() {
        return (this.q + this.a + this.d).hashCode();
    }

    @Override // com.pubmatic.sdk.common.base.c
    public boolean isCompanion() {
        return false;
    }

    public boolean isExpired() {
        return getRemainingExpirationTime() <= 0;
    }

    public boolean isServerSideAuctionWinner() {
        return this.w;
    }

    public boolean isStaticBid() {
        return com.pubmatic.sdk.common.base.c.STATIC_PRICE_BID.equals(this.x);
    }

    @Override // com.pubmatic.sdk.common.base.c
    public boolean isVideo() {
        return this.t;
    }

    public void setHasWon(boolean z) {
        this.y = z;
    }

    @NonNull
    public String toString() {
        StringBuilder sb = new StringBuilder("Price=");
        sb.append(this.c);
        sb.append("PartnerName=");
        sb.append(this.f);
        sb.append("impressionId");
        sb.append(this.a);
        sb.append("bidId");
        sb.append(this.b);
        sb.append("creativeId=");
        sb.append(this.h);
        if (this.n != null) {
            sb.append("Summary List:");
            sb.append(this.n.toString());
        }
        if (this.o != null) {
            sb.append("Reward List:");
            sb.append(this.o.toString());
        }
        if (this.p != null) {
            sb.append(" Prebid targeting Info:");
            sb.append(this.p.toString());
        }
        return sb.toString();
    }

    private static void a(@NonNull f fVar, @NonNull f fVar2) {
        fVar.a = fVar2.a;
        fVar.b = fVar2.b;
        fVar.c = fVar2.c;
        fVar.d = fVar2.d;
        fVar.e = fVar2.e;
        fVar.v = fVar2.v;
        fVar.f = fVar2.f;
        fVar.h = fVar2.h;
        fVar.i = fVar2.i;
        fVar.j = fVar2.j;
        fVar.k = fVar2.k;
        fVar.l = fVar2.l;
        fVar.m = fVar2.m;
        fVar.n = fVar2.n;
        fVar.o = fVar2.o;
        fVar.t = fVar2.t;
        fVar.s = fVar2.s;
        fVar.g = fVar2.g;
        fVar.w = fVar2.w;
        fVar.q = fVar2.q;
        fVar.r = fVar2.r;
        fVar.x = fVar2.x;
        fVar.z = fVar2.z;
        fVar.A = fVar2.A;
    }
}
