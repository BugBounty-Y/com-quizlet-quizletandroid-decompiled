package com.appsflyer.internal;

import androidx.annotation.NonNull;
import com.appsflyer.AFLogger;
import com.appsflyer.internal.components.network.http.exceptions.HttpException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;

/* loaded from: classes.dex */
public final class AFf1qSDK extends AFe1sSDK<AFf1nSDK> {
    public final AFf1mSDK areAllFieldsValid;
    public AFf1nSDK component1;
    private final AFf1pSDK component2;
    public AFi1vSDK component3;
    private final AFc1pSDK component4;
    private final AFf1gSDK copy;
    private final AFf1lSDK copydefault;
    private final String equals;
    private final AFf1iSDK hashCode;
    private final AFd1oSDK toString;

    public AFf1qSDK(@NonNull AFf1pSDK aFf1pSDK, @NonNull AFc1pSDK aFc1pSDK, @NonNull AFf1gSDK aFf1gSDK, @NonNull AFf1lSDK aFf1lSDK, @NonNull AFd1oSDK aFd1oSDK, @NonNull AFf1iSDK aFf1iSDK, @NonNull String str, AFf1mSDK aFf1mSDK) {
        super(AFe1mSDK.RC_CDN, new AFe1mSDK[0], "UpdateRemoteConfiguration");
        this.component1 = null;
        this.component2 = aFf1pSDK;
        this.component4 = aFc1pSDK;
        this.copy = aFf1gSDK;
        this.copydefault = aFf1lSDK;
        this.toString = aFd1oSDK;
        this.hashCode = aFf1iSDK;
        this.equals = str;
        this.areAllFieldsValid = aFf1mSDK;
    }

    private void AFAdRevenueData(String str, long j, AFi1ySDK aFi1ySDK, String str2, AFd1aSDK<AFi1wSDK> aFd1aSDK) {
        getRevenue(str, j, aFd1aSDK, aFd1aSDK != null ? aFd1aSDK.getBody() : null, aFi1ySDK, str2 != null ? str2 : null, null);
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x0051  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x005d A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private com.appsflyer.internal.AFf1nSDK component1() throws java.lang.InterruptedException, java.security.NoSuchAlgorithmException, java.security.InvalidKeyException, java.io.InterruptedIOException {
        /*
            Method dump skipped, instructions count: 555
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.appsflyer.internal.AFf1qSDK.component1():com.appsflyer.internal.AFf1nSDK");
    }

    private void getRevenue(String str, long j, AFd1aSDK<?> aFd1aSDK, AFi1wSDK aFi1wSDK, AFi1ySDK aFi1ySDK, String str2, Throwable th) {
        long j2;
        int statusCode;
        Throwable th2;
        if (aFd1aSDK != null) {
            j2 = aFd1aSDK.getRevenue.getRevenue;
            statusCode = aFd1aSDK.getStatusCode();
        } else {
            j2 = 0;
            statusCode = 0;
        }
        int i = statusCode;
        if (th instanceof HttpException) {
            Throwable cause = th.getCause();
            j2 = ((HttpException) th).getMetrics().getRevenue;
            th2 = cause;
        } else {
            th2 = th;
        }
        this.component3 = new AFi1vSDK(aFi1wSDK != null ? aFi1wSDK.getRevenue : null, str, j2, System.currentTimeMillis() - j, i, aFi1ySDK, str2, th2);
    }

    @Override // com.appsflyer.internal.AFe1sSDK
    @NonNull
    public final AFe1rSDK getCurrencyIso4217Code() throws Exception {
        try {
            AFf1nSDK aFf1nSDKComponent1 = component1();
            this.component1 = aFf1nSDKComponent1;
            return aFf1nSDKComponent1 == AFf1nSDK.FAILURE ? AFe1rSDK.FAILURE : AFe1rSDK.SUCCESS;
        } catch (InterruptedIOException e) {
            e = e;
            AFLogger.INSTANCE.e(AFg1cSDK.REMOTE_CONTROL, "RC update config failed", e, false, false, false);
            this.component1 = AFf1nSDK.FAILURE;
            return AFe1rSDK.TIMEOUT;
        } catch (InterruptedException e2) {
            e = e2;
            AFLogger.INSTANCE.e(AFg1cSDK.REMOTE_CONTROL, "RC update config failed", e, false, false, false);
            this.component1 = AFf1nSDK.FAILURE;
            return AFe1rSDK.TIMEOUT;
        } catch (SocketTimeoutException unused) {
            this.component1 = AFf1nSDK.FAILURE;
            return AFe1rSDK.TIMEOUT;
        }
    }

    @Override // com.appsflyer.internal.AFe1sSDK
    public final boolean getMediationNetwork() {
        return false;
    }

    @Override // com.appsflyer.internal.AFe1sSDK
    public final long getMonetizationNetwork() {
        return 1500L;
    }
}
