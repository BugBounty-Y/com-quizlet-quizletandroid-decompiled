package com.pubmatic.sdk.openwrap.core;

import com.pubmatic.sdk.common.models.a;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class o extends com.pubmatic.sdk.common.base.f implements com.pubmatic.sdk.common.base.o, com.pubmatic.sdk.common.base.a {

    @NotNull
    private final String a;
    private com.pubmatic.sdk.common.base.g b;

    @NotNull
    private final com.pubmatic.sdk.common.base.p c;

    @NotNull
    private final com.pubmatic.sdk.common.base.b d;
    private com.pubmatic.sdk.common.models.a e;

    public o(@NotNull String bidResponse) {
        Intrinsics.checkNotNullParameter(bidResponse, "bidResponse");
        this.a = bidResponse;
        com.pubmatic.sdk.openwrap.core.internal.b bVar = new com.pubmatic.sdk.openwrap.core.internal.b();
        this.c = bVar;
        bVar.setListener(this);
        com.pubmatic.sdk.openwrap.core.internal.a aVar = new com.pubmatic.sdk.openwrap.core.internal.a();
        this.d = aVar;
        aVar.setListener(this);
        setIdentifier("EXT_BID_HANDLER");
    }

    private final com.pubmatic.sdk.common.models.a a(com.pubmatic.sdk.common.models.a aVar) {
        List<com.pubmatic.sdk.common.base.c> bids = aVar.getBids();
        Intrinsics.checkNotNullExpressionValue(bids, "adDescriptor.bids");
        if (bids.isEmpty()) {
            return null;
        }
        f fVar = (f) aVar.getBids().get(0);
        a.C0010a c0010a = new a.C0010a(aVar.getBids());
        c0010a.setWinningBid(fVar);
        c0010a.setRefreshInterval(0);
        c0010a.setServerSidePartnerBids(aVar.getBids());
        return c0010a.build();
    }

    @Override // com.pubmatic.sdk.common.base.a
    public void adBuilderOnSuccess(@NotNull com.pubmatic.sdk.common.models.a adDescriptor) {
        Unit unit;
        com.pubmatic.sdk.common.base.g gVar;
        com.pubmatic.sdk.common.base.g gVar2;
        Intrinsics.checkNotNullParameter(adDescriptor, "adDescriptor");
        com.pubmatic.sdk.common.models.a aVarA = a(adDescriptor);
        this.e = aVarA;
        if (aVarA == null || (gVar2 = this.b) == null) {
            unit = null;
        } else {
            gVar2.onBidsFetched(this, aVarA);
            unit = Unit.a;
        }
        if (unit != null || (gVar = this.b) == null) {
            return;
        }
        gVar.onBidsFailed(this, new com.pubmatic.sdk.common.h(1002, "No ads available"));
    }

    @Override // com.pubmatic.sdk.common.base.f, com.pubmatic.sdk.common.base.i
    public void destroy() {
        this.bidderListener = null;
        this.e = null;
    }

    @Override // com.pubmatic.sdk.common.base.f, com.pubmatic.sdk.common.base.i
    public com.pubmatic.sdk.common.models.a getAdResponse() {
        return this.e;
    }

    @Override // com.pubmatic.sdk.common.base.f, com.pubmatic.sdk.common.base.i
    @NotNull
    public Map<String, com.pubmatic.sdk.common.base.h> getBidderResults() {
        return new HashMap();
    }

    @Override // com.pubmatic.sdk.common.base.o
    public void parserOnError(@NotNull com.pubmatic.sdk.common.h error) {
        Intrinsics.checkNotNullParameter(error, "error");
        com.pubmatic.sdk.common.base.g gVar = this.b;
        if (gVar == null) {
            return;
        }
        gVar.onBidsFailed(this, error);
    }

    @Override // com.pubmatic.sdk.common.base.o
    public void parserOnSuccess(@NotNull com.pubmatic.sdk.common.models.a adResponse) {
        Intrinsics.checkNotNullParameter(adResponse, "adResponse");
        this.d.build(new a.C0010a(adResponse).build());
    }

    @Override // com.pubmatic.sdk.common.base.f, com.pubmatic.sdk.common.base.i
    public void requestBid() {
        try {
            this.c.parse(new JSONObject(this.a));
        } catch (JSONException e) {
            com.pubmatic.sdk.common.base.g gVar = this.b;
            if (gVar == null) {
                return;
            }
            gVar.onBidsFailed(this, new com.pubmatic.sdk.common.h(1007, e.toString()));
        }
    }

    @Override // com.pubmatic.sdk.common.base.f, com.pubmatic.sdk.common.base.i
    public void setBidderListener(com.pubmatic.sdk.common.base.g gVar) {
        this.b = gVar;
    }
}
