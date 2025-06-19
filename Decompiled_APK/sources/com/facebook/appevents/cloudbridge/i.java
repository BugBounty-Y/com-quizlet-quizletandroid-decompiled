package com.facebook.appevents.cloudbridge;

import com.appsflyer.AdRevenueScheme;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;

/* loaded from: classes.dex */
public enum i {
    VALUE_TO_SUM("value"),
    EVENT_TIME("event_time"),
    EVENT_NAME("event_name"),
    CONTENT_IDS("content_ids"),
    CONTENTS("contents"),
    CONTENT_TYPE("content_type"),
    DESCRIPTION(OTUXParamsKeys.OT_UX_DESCRIPTION),
    LEVEL("level"),
    MAX_RATING_VALUE("max_rating_value"),
    NUM_ITEMS("num_items"),
    PAYMENT_INFO_AVAILABLE("payment_info_available"),
    REGISTRATION_METHOD("registration_method"),
    SEARCH_STRING("search_string"),
    SUCCESS("success"),
    ORDER_ID("order_id"),
    AD_TYPE(AdRevenueScheme.AD_TYPE),
    CURRENCY("currency");

    public final String a;

    i(String str) {
        this.a = str;
    }
}
