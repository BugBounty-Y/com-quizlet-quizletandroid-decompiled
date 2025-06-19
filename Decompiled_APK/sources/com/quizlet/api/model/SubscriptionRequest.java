package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class SubscriptionRequest {

    @JsonProperty
    protected List<Data> data = new ArrayList();

    public static class Data {

        @JsonProperty
        public final String orderId;

        @JsonProperty
        public final String packageName;

        @JsonProperty
        public final long priceAmountMicros;

        @JsonProperty
        public final String priceCurrencyCode;

        @JsonProperty
        public final String productId;

        @JsonProperty
        public final String source;

        @JsonProperty
        public final String token;

        @JsonProperty
        public final long userId;

        public Data(IPurchase iPurchase, ISkuDetails iSkuDetails, long j, String str) {
            this.source = str;
            this.userId = j;
            this.token = iPurchase.getToken();
            this.packageName = iPurchase.getPackageName();
            this.productId = iPurchase.getSku();
            this.orderId = iPurchase.getOrderId();
            this.priceAmountMicros = iSkuDetails.getPriceAmountMicros();
            this.priceCurrencyCode = iSkuDetails.getPriceCurrencyCode();
        }
    }

    public SubscriptionRequest(IPurchase iPurchase, ISkuDetails iSkuDetails, long j, String str) {
        this.data.add(new Data(iPurchase, iSkuDetails, j, str));
    }
}
