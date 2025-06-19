package org.prebid.mobile.rendering.bidding.data.bid;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import org.json.JSONObject;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.Ext;
import org.prebid.mobile.rendering.models.openrtb.bidRequests.MobileSdkPassThrough;

/* loaded from: classes3.dex */
public class BidResponse {
    public ArrayList a;
    public Ext b;
    public boolean c;
    public boolean d;
    public String e;
    public JSONObject f;
    public MobileSdkPassThrough g;

    public final HashMap a() {
        HashMap map = new HashMap();
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            Iterator it3 = ((Seatbid) it2.next()).a.iterator();
            while (it3.hasNext()) {
                Bid bid = (Bid) it3.next();
                if (bid.c == null) {
                    bid.c = new Prebid();
                }
                Prebid prebid = bid.c;
                if (prebid != null) {
                    if (prebid == null) {
                        bid.c = new Prebid();
                    }
                    map.putAll(bid.c.a);
                }
            }
        }
        return map;
    }

    public final Bid b() {
        ArrayList arrayList = this.a;
        if (arrayList == null) {
            return null;
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            Iterator it3 = ((Seatbid) it2.next()).a.iterator();
            while (it3.hasNext()) {
                Bid bid = (Bid) it3.next();
                if (bid.c == null) {
                    bid.c = new Prebid();
                }
                Prebid prebid = bid.c;
                boolean z = false;
                if (prebid != null) {
                    HashMap map = prebid.a;
                    if (!map.isEmpty()) {
                        boolean z2 = map.containsKey("hb_pb") && map.containsKey("hb_bidder");
                        if (!this.d) {
                            z = z2;
                        } else if (z2 && map.containsKey("hb_cache_id")) {
                            z = true;
                        }
                    }
                }
                if (z) {
                    return bid;
                }
            }
        }
        return null;
    }
}
