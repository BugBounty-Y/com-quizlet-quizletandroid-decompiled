package com.pubmatic.sdk.openwrap.core;

import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.models.a;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* loaded from: classes2.dex */
public class l extends com.pubmatic.sdk.common.base.f implements com.pubmatic.sdk.common.base.g {

    @NonNull
    private final com.pubmatic.sdk.common.base.i a;
    private com.pubmatic.sdk.common.models.a b;

    public l(@NonNull com.pubmatic.sdk.common.base.i iVar) {
        this.a = iVar;
        iVar.setBidderListener(this);
    }

    /* JADX WARN: Multi-variable type inference failed */
    private void a(@NonNull com.pubmatic.sdk.common.base.i iVar) {
        String identifier = iVar.getIdentifier();
        com.pubmatic.sdk.common.base.h hVar = iVar.getBidderResults().get(identifier);
        ArrayList arrayList = new ArrayList();
        if (hVar != null) {
            com.pubmatic.sdk.common.network.l networkResult = hVar.getNetworkResult();
            if (networkResult != null) {
                POBLog.info("POBBiddingManager", "Network result for bidder %s is : %s", identifier, networkResult.toString());
            }
            com.pubmatic.sdk.common.models.a adResponse = hVar.getAdResponse();
            if (adResponse != null) {
                arrayList.addAll(adResponse.getBids());
            }
        }
        if (this.bidderListener != null) {
            if (arrayList.isEmpty()) {
                a();
                return;
            }
            com.pubmatic.sdk.common.models.a adResponse2 = this.a.getAdResponse() != null ? this.a.getAdResponse() : com.pubmatic.sdk.common.models.a.defaultResponse();
            List<com.pubmatic.sdk.common.base.c> bids = adResponse2.getBids();
            f fVar = null;
            if (adResponse2.isSendAllBidsEnabled()) {
                Iterator<com.pubmatic.sdk.common.base.c> it2 = bids.iterator();
                while (true) {
                    if (!it2.hasNext()) {
                        break;
                    }
                    f fVar2 = (f) it2.next();
                    if (fVar2.isServerSideAuctionWinner()) {
                        fVar = fVar2;
                        break;
                    }
                }
                if (fVar == null && !bids.isEmpty()) {
                    fVar = (f) bids.get(0);
                }
            } else if (!arrayList.isEmpty()) {
                fVar = (f) arrayList.get(0);
            }
            if (fVar != null) {
                this.bidderListener.onBidsFetched(this, a(fVar, bids));
            } else {
                a();
            }
            arrayList.clear();
        }
    }

    public static f getWinningBid(com.pubmatic.sdk.common.models.a aVar) {
        if (aVar != null) {
            return (f) aVar.getWinningBid();
        }
        return null;
    }

    @Override // com.pubmatic.sdk.common.base.f, com.pubmatic.sdk.common.base.i
    public void destroy() {
        this.a.destroy();
    }

    @Override // com.pubmatic.sdk.common.base.f, com.pubmatic.sdk.common.base.i
    public com.pubmatic.sdk.common.models.a getAdResponse() {
        return this.b;
    }

    @Override // com.pubmatic.sdk.common.base.f, com.pubmatic.sdk.common.base.i
    @NonNull
    public Map<String, com.pubmatic.sdk.common.base.h> getBidderResults() {
        return this.a.getBidderResults();
    }

    @Override // com.pubmatic.sdk.common.base.g
    public void onBidsFailed(@NonNull com.pubmatic.sdk.common.base.i iVar, @NonNull com.pubmatic.sdk.common.h hVar) {
        a(iVar);
    }

    @Override // com.pubmatic.sdk.common.base.g
    public void onBidsFetched(@NonNull com.pubmatic.sdk.common.base.i iVar, @NonNull com.pubmatic.sdk.common.models.a aVar) {
        a(iVar);
    }

    @Override // com.pubmatic.sdk.common.base.f, com.pubmatic.sdk.common.base.i
    public void requestBid() {
        this.a.requestBid();
    }

    @NonNull
    private com.pubmatic.sdk.common.models.a a(@NonNull f fVar, @NonNull List<f> list) {
        a.C0010a c0010a = new a.C0010a(list);
        c0010a.setWinningBid(fVar);
        com.pubmatic.sdk.common.models.a adResponse = this.a.getAdResponse();
        if (adResponse != null) {
            c0010a.setRefreshInterval(adResponse.getRefreshInterval());
            c0010a.setSendAllBidsState(adResponse.isSendAllBidsEnabled());
        } else {
            c0010a.setRefreshInterval(30);
        }
        c0010a.setServerSidePartnerBids(list);
        com.pubmatic.sdk.common.models.a aVarBuild = c0010a.build();
        this.b = aVarBuild;
        return aVarBuild;
    }

    private void a() {
        String strM;
        com.pubmatic.sdk.common.base.h hVar = this.a.getBidderResults().get(this.a.getIdentifier());
        if (hVar != null && hVar.getError() != null) {
            strM = android.support.v4.media.session.a.m(" ", this.a.getIdentifier(), " : ", hVar.getError().toString());
        } else {
            strM = "";
        }
        if (strM.isEmpty()) {
            strM = "No Ads available from any bidder";
        }
        com.pubmatic.sdk.common.base.g gVar = this.bidderListener;
        if (gVar != null) {
            gVar.onBidsFailed(this, new com.pubmatic.sdk.common.h(1002, strM));
        }
    }
}
