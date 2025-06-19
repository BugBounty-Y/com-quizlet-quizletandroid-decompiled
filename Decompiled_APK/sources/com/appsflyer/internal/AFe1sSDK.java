package com.appsflyer.internal;

import android.net.TrafficStats;
import androidx.annotation.NonNull;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes.dex */
public abstract class AFe1sSDK<Result> implements Comparable<AFe1sSDK<?>>, Callable<AFe1rSDK> {
    private static final AtomicInteger component4 = new AtomicInteger();

    @NonNull
    public final Set<AFe1mSDK> AFAdRevenueData;
    private Throwable areAllFieldsValid;
    private final String component1;
    private final int component2;
    private long component3;

    @NonNull
    public final Set<AFe1mSDK> getCurrencyIso4217Code;
    public AFe1rSDK getMediationNetwork;

    @NonNull
    public final AFe1mSDK getMonetizationNetwork;
    public volatile int getRevenue;
    private boolean hashCode;

    public AFe1sSDK(@NonNull AFe1mSDK aFe1mSDK, @NonNull AFe1mSDK[] aFe1mSDKArr, String str) {
        HashSet hashSet = new HashSet();
        this.getCurrencyIso4217Code = hashSet;
        this.AFAdRevenueData = new HashSet();
        int iIncrementAndGet = component4.incrementAndGet();
        this.component2 = iIncrementAndGet;
        this.hashCode = false;
        this.getRevenue = 0;
        this.getMonetizationNetwork = aFe1mSDK;
        Collections.addAll(hashSet, aFe1mSDKArr);
        if (str != null) {
            this.component1 = str;
        } else {
            this.component1 = String.valueOf(iIncrementAndGet);
        }
    }

    public void AFAdRevenueData() {
        this.hashCode = true;
    }

    public final boolean areAllFieldsValid() {
        return this.hashCode;
    }

    @Override // java.util.concurrent.Callable
    /* renamed from: component2, reason: merged with bridge method [inline-methods] */
    public final AFe1rSDK call() throws Exception {
        TrafficStats.setThreadStatsTag(82339054);
        this.getMediationNetwork = null;
        this.areAllFieldsValid = null;
        long jCurrentTimeMillis = System.currentTimeMillis();
        this.getRevenue++;
        try {
            AFe1rSDK currencyIso4217Code = getCurrencyIso4217Code();
            this.getMediationNetwork = currencyIso4217Code;
            return currencyIso4217Code;
        } finally {
        }
    }

    public final Throwable component4() {
        return this.areAllFieldsValid;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        AFe1sSDK aFe1sSDK = (AFe1sSDK) obj;
        if (this.getMonetizationNetwork != aFe1sSDK.getMonetizationNetwork) {
            return false;
        }
        return this.component1.equals(aFe1sSDK.component1);
    }

    @NonNull
    public abstract AFe1rSDK getCurrencyIso4217Code() throws Exception;

    public void getCurrencyIso4217Code(Throwable th) {
    }

    public abstract boolean getMediationNetwork();

    public abstract long getMonetizationNetwork();

    public void getRevenue() {
    }

    public final int hashCode() {
        return this.component1.hashCode() + (this.getMonetizationNetwork.hashCode() * 31);
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.getMonetizationNetwork);
        sb.append("-");
        sb.append(this.component1);
        String string = sb.toString();
        if (String.valueOf(this.component2).equals(this.component1)) {
            return string;
        }
        StringBuilder sbX = android.support.v4.media.session.a.x(string, "-");
        sbX.append(this.component2);
        return sbX.toString();
    }

    @Override // java.lang.Comparable
    /* renamed from: getCurrencyIso4217Code, reason: merged with bridge method [inline-methods] */
    public final int compareTo(AFe1sSDK<?> aFe1sSDK) {
        int i = this.getMonetizationNetwork.w - aFe1sSDK.getMonetizationNetwork.w;
        if (i != 0) {
            return i;
        }
        if (this.component1.equals(aFe1sSDK.component1)) {
            return 0;
        }
        return this.component2 - aFe1sSDK.component2;
    }
}
