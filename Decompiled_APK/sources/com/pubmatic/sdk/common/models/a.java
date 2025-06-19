package com.pubmatic.sdk.common.models;

import androidx.annotation.NonNull;
import com.amazon.device.ads.DTBAdSize;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.utility.o;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class a implements com.pubmatic.sdk.common.base.j {

    @NonNull
    private List<com.pubmatic.sdk.common.base.c> a;
    private List<com.pubmatic.sdk.common.base.c> b;
    private com.pubmatic.sdk.common.base.c c;
    private com.pubmatic.sdk.common.base.c d;
    private int e;
    private JSONObject f;
    private boolean g;

    @NonNull
    public static <T extends com.pubmatic.sdk.common.base.c> a defaultResponse() {
        a aVar = new a();
        aVar.a = new ArrayList();
        aVar.e = 30;
        return aVar;
    }

    public com.pubmatic.sdk.common.base.c getBid(String str) {
        if (o.isNullOrEmpty(str)) {
            return null;
        }
        for (com.pubmatic.sdk.common.base.c cVar : this.a) {
            if (str.equals(cVar.getId())) {
                return cVar;
            }
        }
        return null;
    }

    @NonNull
    public List<com.pubmatic.sdk.common.base.c> getBids() {
        return this.a;
    }

    public JSONObject getCustomData() {
        return this.f;
    }

    public com.pubmatic.sdk.common.base.c getNextHighestDynamicBid() {
        return this.d;
    }

    public int getRefreshInterval() {
        return this.e;
    }

    public List<com.pubmatic.sdk.common.base.c> getServerSidePartnerBids() {
        return this.b;
    }

    @Override // com.pubmatic.sdk.common.base.j
    public Map<String, String> getTargetingInfo() {
        Map<String, String> targetingInfo;
        Map<String, String> targetingInfo2;
        HashMap map = new HashMap();
        if (this.g) {
            for (com.pubmatic.sdk.common.base.c cVar : getBids()) {
                if (cVar != null && (targetingInfo2 = cVar.getTargetingInfo()) != null) {
                    try {
                        map.putAll(targetingInfo2);
                    } catch (ClassCastException | IllegalArgumentException | NullPointerException | UnsupportedOperationException unused) {
                        POBLog.error("POBAdResponse", "Failed to add targeting info", new Object[0]);
                    }
                }
            }
        } else {
            com.pubmatic.sdk.common.base.c cVar2 = this.c;
            if (cVar2 != null && (targetingInfo = cVar2.getTargetingInfo()) != null) {
                map.putAll(targetingInfo);
            }
        }
        if (map.size() == 0) {
            return null;
        }
        return map;
    }

    public com.pubmatic.sdk.common.base.c getWinningBid() {
        return this.c;
    }

    public boolean isSendAllBidsEnabled() {
        return this.g;
    }

    /* renamed from: com.pubmatic.sdk.common.models.a$a, reason: collision with other inner class name */
    public static class C0010a {

        @NonNull
        private List<com.pubmatic.sdk.common.base.c> a;
        private List<com.pubmatic.sdk.common.base.c> b;
        private com.pubmatic.sdk.common.base.c c;
        private com.pubmatic.sdk.common.base.c d;
        private int e;
        private JSONObject f;
        private boolean g;

        public C0010a(@NonNull List<com.pubmatic.sdk.common.base.c> list) {
            this.a = list;
        }

        @NonNull
        private List<com.pubmatic.sdk.common.base.c> a(List<com.pubmatic.sdk.common.base.c> list, @NonNull String str) {
            com.pubmatic.sdk.common.base.c cVarBuildWithRefreshAndExpiryTimeout;
            ArrayList arrayList = new ArrayList();
            for (com.pubmatic.sdk.common.base.c cVar : list) {
                if (cVar != null && (cVarBuildWithRefreshAndExpiryTimeout = cVar.buildWithRefreshAndExpiryTimeout(this.e, a(cVar, str))) != null) {
                    arrayList.add(cVarBuildWithRefreshAndExpiryTimeout);
                }
            }
            list.clear();
            list.addAll(arrayList);
            return list;
        }

        @NonNull
        public a build() {
            a aVar = new a();
            aVar.a = this.a;
            aVar.b = this.b;
            aVar.c = this.c;
            aVar.e = this.e;
            aVar.f = this.f;
            aVar.g = this.g;
            aVar.d = this.d;
            return aVar;
        }

        @NonNull
        public C0010a setNextHighestDynamicBid(com.pubmatic.sdk.common.base.c cVar) {
            this.d = cVar;
            return this;
        }

        public C0010a setRefreshInterval(int i) {
            this.e = i;
            return this;
        }

        public C0010a setSendAllBidsState(boolean z) {
            this.g = z;
            return this;
        }

        public C0010a setServerSidePartnerBids(List<com.pubmatic.sdk.common.base.c> list) {
            this.b = list;
            return this;
        }

        public C0010a setWinningBid(com.pubmatic.sdk.common.base.c cVar) {
            this.c = cVar;
            return this;
        }

        public C0010a updateWinningBid(@NonNull com.pubmatic.sdk.common.base.c cVar) {
            if (this.a.remove(cVar)) {
                this.a.add(cVar);
            }
            List<com.pubmatic.sdk.common.base.c> list = this.b;
            if (list != null && list.remove(cVar)) {
                this.b.add(cVar);
            }
            this.c = cVar;
            return this;
        }

        public C0010a updateWithRefreshIntervalAndExpiryTimeout(@NonNull String str) {
            List<com.pubmatic.sdk.common.base.c> list = this.b;
            if (list != null) {
                a(list, str);
            }
            a(this.a, str);
            com.pubmatic.sdk.common.base.c cVar = this.c;
            if (cVar != null) {
                this.c = cVar.buildWithRefreshAndExpiryTimeout(this.e, a(cVar, str));
            }
            return this;
        }

        public C0010a(@NonNull a aVar) {
            this.a = aVar.a;
            this.b = aVar.b;
            this.c = aVar.c;
            this.e = aVar.e;
            this.f = aVar.f;
            this.g = aVar.g;
            this.d = aVar.d;
        }

        private int a(@NonNull com.pubmatic.sdk.common.base.c cVar, @NonNull String str) {
            String str2;
            int iHashCode = str.hashCode();
            if (iHashCode == -1183997287) {
                return (!str.equals("inline") || cVar.isVideo()) ? 3600000 : 300000;
            }
            if (iHashCode == -1052618729) {
                str2 = com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_NATIVE;
            } else {
                if (iHashCode != 604727084) {
                    return 3600000;
                }
                str2 = DTBAdSize.AAX_INTERSTITIAL_AD_SIZE;
            }
            str.equals(str2);
            return 3600000;
        }

        public C0010a(@NonNull JSONObject jSONObject) {
            this.a = new ArrayList();
            this.f = jSONObject;
        }
    }

    private a() {
        this.a = new ArrayList();
    }
}
