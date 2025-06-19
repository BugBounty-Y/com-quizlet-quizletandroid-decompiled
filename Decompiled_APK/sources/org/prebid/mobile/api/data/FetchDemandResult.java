package org.prebid.mobile.api.data;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes3.dex */
public final class FetchDemandResult {
    public static final FetchDemandResult a;
    public static final FetchDemandResult b;
    public static final FetchDemandResult c;
    public static final FetchDemandResult d;
    public static final FetchDemandResult e;
    public static final FetchDemandResult f;
    public static final FetchDemandResult g;
    public static final /* synthetic */ FetchDemandResult[] h;

    /* JADX INFO: Fake field, exist only in values array */
    FetchDemandResult EF0;

    static {
        FetchDemandResult fetchDemandResult = new FetchDemandResult("SUCCESS", 0);
        FetchDemandResult fetchDemandResult2 = new FetchDemandResult("INVALID_ACCOUNT_ID", 1);
        a = fetchDemandResult2;
        FetchDemandResult fetchDemandResult3 = new FetchDemandResult("INVALID_CONFIG_ID", 2);
        b = fetchDemandResult3;
        FetchDemandResult fetchDemandResult4 = new FetchDemandResult("INVALID_SIZE", 3);
        c = fetchDemandResult4;
        FetchDemandResult fetchDemandResult5 = new FetchDemandResult("INVALID_CONTEXT", 4);
        FetchDemandResult fetchDemandResult6 = new FetchDemandResult("INVALID_AD_OBJECT", 5);
        FetchDemandResult fetchDemandResult7 = new FetchDemandResult("INVALID_HOST_URL", 6);
        FetchDemandResult fetchDemandResult8 = new FetchDemandResult("NETWORK_ERROR", 7);
        d = fetchDemandResult8;
        FetchDemandResult fetchDemandResult9 = new FetchDemandResult("TIMEOUT", 8);
        e = fetchDemandResult9;
        FetchDemandResult fetchDemandResult10 = new FetchDemandResult("NO_BIDS", 9);
        f = fetchDemandResult10;
        FetchDemandResult fetchDemandResult11 = new FetchDemandResult("SERVER_ERROR", 10);
        g = fetchDemandResult11;
        h = new FetchDemandResult[]{fetchDemandResult, fetchDemandResult2, fetchDemandResult3, fetchDemandResult4, fetchDemandResult5, fetchDemandResult6, fetchDemandResult7, fetchDemandResult8, fetchDemandResult9, fetchDemandResult10, fetchDemandResult11};
    }

    public static FetchDemandResult valueOf(String str) {
        return (FetchDemandResult) Enum.valueOf(FetchDemandResult.class, str);
    }

    public static FetchDemandResult[] values() {
        return (FetchDemandResult[]) h.clone();
    }
}
