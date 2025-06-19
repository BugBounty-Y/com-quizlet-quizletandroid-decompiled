package com.appsflyer.internal;

import com.appsflyer.AFLogger;
import com.appsflyer.attribution.AppsFlyerRequestListener;
import com.appsflyer.deeplink.DeepLink;
import com.appsflyer.deeplink.DeepLinkResult;
import com.appsflyer.internal.AFj1qSDK;
import com.appsflyer.internal.components.network.http.ResponseNetwork;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Observable;
import java.util.Observer;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import kotlin.Pair;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class AFf1xSDK extends AFe1dSDK<AFa1mSDK> {
    private int AFInAppEventParameterName;

    @NotNull
    private final List<AFj1qSDK> AFInAppEventType;
    private int AFKeystoreWrapper;
    private int AFLogger;

    @NotNull
    private final AFa1pSDK component2;

    @NotNull
    private final AFh1vSDK copy;

    @NotNull
    private final AFc1kSDK copydefault;

    @NotNull
    private final AFc1pSDK equals;

    @NotNull
    private final AFa1oSDK hashCode;

    @NotNull
    private final CountDownLatch registerClient;

    @NotNull
    private final AFj1sSDK toString;

    public /* synthetic */ class AFa1tSDK {
        public static final /* synthetic */ int[] AFAdRevenueData;
        public static final /* synthetic */ int[] getRevenue;

        static {
            int[] iArr = new int[AFe1rSDK.values().length];
            try {
                iArr[AFe1rSDK.SUCCESS.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[AFe1rSDK.FAILURE.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            getRevenue = iArr;
            int[] iArr2 = new int[AFj1qSDK.AFa1ySDK.values().length];
            try {
                iArr2[AFj1qSDK.AFa1ySDK.FINISHED.ordinal()] = 1;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                iArr2[AFj1qSDK.AFa1ySDK.STARTED.ordinal()] = 2;
            } catch (NoSuchFieldError unused4) {
            }
            AFAdRevenueData = iArr2;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AFf1xSDK(@NotNull AFa1pSDK aFa1pSDK, @NotNull AFc1dSDK aFc1dSDK) {
        super(AFe1mSDK.DLSDK, new AFe1mSDK[]{AFe1mSDK.RC_CDN, AFe1mSDK.FETCH_ADVERTISING_ID}, aFc1dSDK, "DdlSdk");
        Intrinsics.checkNotNullParameter(aFa1pSDK, "");
        Intrinsics.checkNotNullParameter(aFc1dSDK, "");
        this.component2 = aFa1pSDK;
        this.registerClient = new CountDownLatch(1);
        this.AFInAppEventType = new ArrayList();
        AFc1pSDK revenue = aFc1dSDK.getRevenue();
        Intrinsics.checkNotNullExpressionValue(revenue, "");
        this.equals = revenue;
        AFc1kSDK aFc1kSDKAfInfoLog = aFc1dSDK.afInfoLog();
        Intrinsics.checkNotNullExpressionValue(aFc1kSDKAfInfoLog, "");
        this.copydefault = aFc1kSDKAfInfoLog;
        AFa1oSDK aFa1oSDKD = aFc1dSDK.d();
        Intrinsics.checkNotNullExpressionValue(aFa1oSDKD, "");
        this.hashCode = aFa1oSDKD;
        AFh1vSDK aFh1vSDKAreAllFieldsValid = aFc1dSDK.areAllFieldsValid();
        Intrinsics.checkNotNullExpressionValue(aFh1vSDKAreAllFieldsValid, "");
        this.copy = aFh1vSDKAreAllFieldsValid;
        AFj1sSDK aFj1sSDKAFLogger = aFc1dSDK.AFLogger();
        Intrinsics.checkNotNullExpressionValue(aFj1sSDKAFLogger, "");
        this.toString = aFj1sSDKAFLogger;
        AFj1qSDK[] revenue2 = aFj1sSDKAFLogger.getRevenue();
        Intrinsics.checkNotNullExpressionValue(revenue2, "");
        ArrayList arrayList = new ArrayList();
        for (AFj1qSDK aFj1qSDK : revenue2) {
            if (aFj1qSDK != null && aFj1qSDK.component4 != AFj1qSDK.AFa1ySDK.NOT_STARTED) {
                arrayList.add(aFj1qSDK);
            }
        }
        this.AFInAppEventParameterName = arrayList.size();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            final AFj1qSDK aFj1qSDK2 = (AFj1qSDK) it2.next();
            AFj1qSDK.AFa1ySDK aFa1ySDK = aFj1qSDK2.component4;
            int i = aFa1ySDK == null ? -1 : AFa1tSDK.AFAdRevenueData[aFa1ySDK.ordinal()];
            if (i == 1) {
                AFg1gSDK.d$default(AFLogger.INSTANCE, AFg1cSDK.DDL, aFj1qSDK2.AFAdRevenueData.get("source") + " referrer collected earlier", false, 4, null);
                Intrinsics.checkNotNullExpressionValue(aFj1qSDK2, "");
                getMediationNetwork(aFj1qSDK2);
            } else if (i == 2) {
                aFj1qSDK2.addObserver(new Observer() { // from class: com.appsflyer.internal.j
                    @Override // java.util.Observer
                    public final void update(Observable observable, Object obj) {
                        AFf1xSDK.getMonetizationNetwork(aFj1qSDK2, this, observable, obj);
                    }
                });
            }
        }
    }

    private static Map<String, String> AFAdRevenueData(AFb1mSDK aFb1mSDK) {
        String str;
        if (aFb1mSDK == null || (str = aFb1mSDK.getMonetizationNetwork) == null) {
            return null;
        }
        Intrinsics.checkNotNullExpressionValue(str, "");
        Boolean bool = aFb1mSDK.getMediationNetwork;
        if (bool == null || !bool.booleanValue()) {
            return V.f(new Pair(DBUserFields.Names.USER_UPGRADE_TYPE, "unhashed"), new Pair("value", str));
        }
        return null;
    }

    private final boolean copy() {
        Object obj = this.component2.AFAdRevenueData.get("referrers");
        List list = obj instanceof List ? (List) obj : null;
        return (list != null ? list.size() : 0) < this.AFInAppEventParameterName && !this.component2.AFAdRevenueData.containsKey("referrers");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void getMonetizationNetwork(AFj1qSDK aFj1qSDK, AFf1xSDK aFf1xSDK, Observable observable, Object obj) {
        Intrinsics.checkNotNullParameter(aFf1xSDK, "");
        AFg1gSDK.d$default(AFLogger.INSTANCE, AFg1cSDK.DDL, aFj1qSDK.AFAdRevenueData.get("source") + " referrer collected via observer", false, 4, null);
        Intrinsics.e(observable, "");
        aFf1xSDK.getMediationNetwork((AFj1qSDK) observable);
    }

    @Override // com.appsflyer.internal.AFe1dSDK
    public final boolean a_() {
        return false;
    }

    @Override // com.appsflyer.internal.AFe1dSDK
    public final /* bridge */ /* synthetic */ AppsFlyerRequestListener component3() {
        return null;
    }

    @Override // com.appsflyer.internal.AFe1dSDK
    public final boolean copydefault() {
        return false;
    }

    @Override // com.appsflyer.internal.AFe1dSDK, com.appsflyer.internal.AFe1sSDK
    @NotNull
    public final AFe1rSDK getCurrencyIso4217Code() throws InterruptedException {
        AFe1rSDK currencyIso4217Code;
        AFe1rSDK aFe1rSDK = AFe1rSDK.FAILURE;
        try {
            currencyIso4217Code = super.getCurrencyIso4217Code();
            Intrinsics.checkNotNullExpressionValue(currencyIso4217Code, "");
        } catch (Exception e) {
            e = e;
        }
        try {
            AFh1vSDK aFh1vSDK = this.copy;
            int i = this.AFLogger;
            if (i <= 0 || i > 2) {
                AFLogger.afErrorLogForExcManagerOnly("Unexpected ddl requestCount - end", new IllegalStateException("Metrics: Unexpected ddl requestCount = ".concat(String.valueOf(i))));
            } else {
                int i2 = i - 1;
                aFh1vSDK.component2[i2] = System.currentTimeMillis();
                long j = aFh1vSDK.component1[i2];
                if (j != 0) {
                    long[] jArr = aFh1vSDK.component4;
                    jArr[i2] = aFh1vSDK.component2[i2] - j;
                    aFh1vSDK.getMonetizationNetwork.put("net", jArr);
                    aFh1vSDK.getCurrencyIso4217Code.getMediationNetwork("ddl", new JSONObject(aFh1vSDK.getMonetizationNetwork).toString());
                } else {
                    StringBuilder sb = new StringBuilder("Metrics: ddlStart[");
                    sb.append(i2);
                    sb.append("] ts is missing");
                    AFLogger.afInfoLog(sb.toString());
                }
            }
            int i3 = AFa1tSDK.getRevenue[currencyIso4217Code.ordinal()];
            if (i3 != 1) {
                if (i3 != 2) {
                    return currencyIso4217Code;
                }
                AFLogger aFLogger = AFLogger.INSTANCE;
                AFg1cSDK aFg1cSDK = AFg1cSDK.DDL;
                ResponseNetwork responseNetwork = ((AFe1dSDK) this).component1;
                AFg1gSDK.d$default(aFLogger, aFg1cSDK, "Error occurred. Server response code = " + (responseNetwork != null ? Integer.valueOf(responseNetwork.getStatusCode()) : null), false, 4, null);
                DeepLinkResult deepLinkResult = new DeepLinkResult(null, DeepLinkResult.Error.HTTP_STATUS_CODE);
                this.copy.getMediationNetwork(deepLinkResult, this.hashCode.component3);
                this.hashCode.getRevenue(deepLinkResult);
                return currencyIso4217Code;
            }
            ResponseNetwork responseNetwork2 = ((AFe1dSDK) this).component1;
            Intrinsics.d(responseNetwork2);
            Object body = responseNetwork2.getBody();
            Intrinsics.checkNotNullExpressionValue(body, "");
            AFa1mSDK aFa1mSDK = (AFa1mSDK) body;
            DeepLink deepLink = aFa1mSDK.getCurrencyIso4217Code;
            if (deepLink != null) {
                DeepLinkResult deepLinkResult2 = new DeepLinkResult(deepLink, null);
                this.copy.getMediationNetwork(deepLinkResult2, this.hashCode.component3);
                this.hashCode.getRevenue(deepLinkResult2);
                return currencyIso4217Code;
            }
            if (this.AFLogger > 1 || !aFa1mSDK.getRevenue() || !copy()) {
                DeepLinkResult deepLinkResult3 = new DeepLinkResult(null, null);
                this.copy.getMediationNetwork(deepLinkResult3, this.hashCode.component3);
                this.hashCode.getRevenue(deepLinkResult3);
                return currencyIso4217Code;
            }
            AFg1gSDK.d$default(AFLogger.INSTANCE, AFg1cSDK.DDL, "Waiting for referrers...", false, 4, null);
            this.registerClient.await();
            AFh1vSDK aFh1vSDK2 = this.copy;
            long jCurrentTimeMillis = System.currentTimeMillis();
            long j2 = aFh1vSDK2.component2[0];
            if (j2 != 0) {
                aFh1vSDK2.getMonetizationNetwork.put("rfr_wait", Long.valueOf(jCurrentTimeMillis - j2));
                aFh1vSDK2.getCurrencyIso4217Code.getMediationNetwork("ddl", new JSONObject(aFh1vSDK2.getMonetizationNetwork).toString());
            } else {
                AFLogger.afInfoLog("Metrics: ddlEnd[0] ts is missing");
            }
            if (this.AFKeystoreWrapper != this.AFInAppEventParameterName) {
                return getCurrencyIso4217Code();
            }
            DeepLinkResult deepLinkResult4 = new DeepLinkResult(null, null);
            this.copy.getMediationNetwork(deepLinkResult4, this.hashCode.component3);
            this.hashCode.getRevenue(deepLinkResult4);
            return AFe1rSDK.SUCCESS;
        } catch (Exception e2) {
            e = e2;
            aFe1rSDK = currencyIso4217Code;
            Throwable cause = e.getCause();
            if (cause instanceof InterruptedException ? true : cause instanceof InterruptedIOException) {
                AFLogger.afErrorLogForExcManagerOnly("[DDL] Timeout", new TimeoutException());
                AFg1gSDK.d$default(AFLogger.INSTANCE, AFg1cSDK.DDL, "Timeout, didn't manage to find deferred deeplink after " + this.AFLogger + " attempt(s) within " + this.hashCode.component3 + " milliseconds", false, 4, null);
                DeepLinkResult deepLinkResult5 = new DeepLinkResult(null, DeepLinkResult.Error.TIMEOUT);
                this.copy.getMediationNetwork(deepLinkResult5, this.hashCode.component3);
                this.hashCode.getRevenue(deepLinkResult5);
                return AFe1rSDK.TIMEOUT;
            }
            if (cause instanceof IOException) {
                AFg1gSDK.d$default(AFLogger.INSTANCE, AFg1cSDK.DDL, "Http Exception: the request was not sent to the server", false, 4, null);
                DeepLinkResult deepLinkResult6 = new DeepLinkResult(null, DeepLinkResult.Error.NETWORK);
                this.copy.getMediationNetwork(deepLinkResult6, this.hashCode.component3);
                this.hashCode.getRevenue(deepLinkResult6);
                return aFe1rSDK;
            }
            AFg1gSDK.d$default(AFLogger.INSTANCE, AFg1cSDK.DDL, "Unexpected Exception: " + e, false, 4, null);
            DeepLinkResult deepLinkResult7 = new DeepLinkResult(null, DeepLinkResult.Error.UNEXPECTED);
            this.copy.getMediationNetwork(deepLinkResult7, this.hashCode.component3);
            this.hashCode.getRevenue(deepLinkResult7);
            return aFe1rSDK;
        }
    }

    @Override // com.appsflyer.internal.AFe1dSDK, com.appsflyer.internal.AFe1sSDK
    public final boolean getMediationNetwork() {
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x0145  */
    @Override // com.appsflyer.internal.AFe1dSDK
    @org.jetbrains.annotations.NotNull
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.appsflyer.internal.AFd1nSDK<com.appsflyer.internal.AFa1mSDK> getRevenue(@org.jetbrains.annotations.NotNull java.lang.String r10) {
        /*
            Method dump skipped, instructions count: 480
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.internal.AFf1xSDK.getRevenue(java.lang.String):com.appsflyer.internal.AFd1nSDK");
    }

    private final void getMediationNetwork(AFj1qSDK aFj1qSDK) {
        if (getMonetizationNetwork(aFj1qSDK)) {
            this.AFInAppEventType.add(aFj1qSDK);
            this.registerClient.countDown();
            AFg1gSDK.d$default(AFLogger.INSTANCE, AFg1cSDK.DDL, "Added non-organic ".concat(aFj1qSDK.getClass().getSimpleName()), false, 4, null);
        } else {
            int i = this.AFKeystoreWrapper + 1;
            this.AFKeystoreWrapper = i;
            if (i == this.AFInAppEventParameterName) {
                this.registerClient.countDown();
            }
        }
    }

    private static boolean getMonetizationNetwork(AFj1qSDK aFj1qSDK) {
        Object obj = aFj1qSDK.AFAdRevenueData.get("click_ts");
        Long l = obj instanceof Long ? (Long) obj : null;
        if (l != null) {
            if (System.currentTimeMillis() - TimeUnit.SECONDS.toMillis(l.longValue()) < TimeUnit.DAYS.toMillis(1L)) {
                return true;
            }
        }
        return false;
    }

    @Override // com.appsflyer.internal.AFe1dSDK, com.appsflyer.internal.AFe1sSDK
    public final long getMonetizationNetwork() {
        return this.hashCode.component3;
    }
}
