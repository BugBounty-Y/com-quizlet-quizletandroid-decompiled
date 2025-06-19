package com.amazon.device.ads;

/* loaded from: classes.dex */
public class DTBCacheData {
    private static long ADMOB_AUTO_REFRESH_TIME_LIMIT_MS = 30000;
    private DTBAdRequest cachingLoader;
    private DTBAdResponse cachingResponse;
    private String requestId;
    private boolean isBidRequestFailed = false;
    private long responseTimeStamp = assistantMode.refactored.a.f();

    public DTBCacheData(String str, DTBAdRequest dTBAdRequest) {
        this.requestId = str;
        this.cachingLoader = dTBAdRequest;
    }

    public void addResponse(DTBAdResponse dTBAdResponse) {
        this.cachingResponse = dTBAdResponse;
        this.responseTimeStamp = assistantMode.refactored.a.f();
    }

    public DTBAdResponse getAdResponse() {
        if (assistantMode.refactored.a.f() - this.responseTimeStamp <= ADMOB_AUTO_REFRESH_TIME_LIMIT_MS) {
            return this.cachingResponse;
        }
        this.cachingResponse = null;
        return null;
    }

    public String getRequestId() {
        return this.requestId;
    }

    public long getResponseTimeStamp() {
        return this.responseTimeStamp;
    }

    public boolean isBidRequestFailed() {
        return this.isBidRequestFailed;
    }

    public void setBidRequestFailed(boolean z) {
        this.isBidRequestFailed = z;
    }

    public void updateResponse(DTBAdResponse dTBAdResponse) {
        this.cachingResponse = dTBAdResponse;
    }
}
