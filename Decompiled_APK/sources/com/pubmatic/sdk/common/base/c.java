package com.pubmatic.sdk.common.base;

import java.util.Map;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public interface c {
    public static final int BID_STATUS_NOT_OK = 0;
    public static final int BID_STATUS_OK = 1;
    public static final String CREATIVE_TYPE_BANNER = "banner";
    public static final String CREATIVE_TYPE_NATIVE = "native";
    public static final String CREATIVE_TYPE_VIDEO = "video";
    public static final String DYNAMIC_PRICE_BID = "dynamic";
    public static final String STATIC_PRICE_BID = "static";

    c buildWithRefreshAndExpiryTimeout(int i, int i2);

    String getBundle();

    int getContentHeight();

    int getContentWidth();

    String getCreativeType();

    int getDspId();

    String getId();

    JSONObject getRawBid();

    int getRefreshInterval();

    String getRenderableContent();

    int getStatus();

    Map<String, String> getTargetingInfo();

    boolean isCompanion();

    boolean isVideo();
}
