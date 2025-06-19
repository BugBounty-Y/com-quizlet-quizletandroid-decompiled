package org.prebid.mobile.rendering.bidding.listeners;

import org.prebid.mobile.api.exceptions.AdException;
import org.prebid.mobile.rendering.bidding.data.bid.BidResponse;

/* loaded from: classes3.dex */
public interface BidRequesterListener {
    void a(AdException adException);

    void b(BidResponse bidResponse);
}
