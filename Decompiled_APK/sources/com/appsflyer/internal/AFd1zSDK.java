package com.appsflyer.internal;

import com.appsflyer.AFLogger;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3336f;
import com.google.firebase.perf.network.FirebasePerfUrlConnection;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.C4931w;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public abstract class AFd1zSDK {
    public int AFAdRevenueData;

    @NotNull
    public byte[] getCurrencyIso4217Code;
    public Map<String, String> getMonetizationNetwork;
    private final boolean getRevenue;

    public AFd1zSDK(@NotNull byte[] bArr, Map<String, String> map, int i) {
        Intrinsics.checkNotNullParameter(bArr, "");
        this.getCurrencyIso4217Code = bArr;
        this.getMonetizationNetwork = map;
        this.AFAdRevenueData = i;
        this.getRevenue = true;
    }

    private static String AFAdRevenueData(HttpURLConnection httpURLConnection) throws IOException {
        InputStream errorStream;
        try {
            errorStream = httpURLConnection.getInputStream();
        } catch (Throwable th) {
            AFLogger aFLogger = AFLogger.INSTANCE;
            AFg1cSDK aFg1cSDK = AFg1cSDK.HTTP_CLIENT;
            String message = th.getMessage();
            AFg1gSDK.e$default(aFLogger, aFg1cSDK, message == null ? "" : message, th, false, false, false, false, 96, null);
            errorStream = httpURLConnection.getErrorStream();
        }
        if (errorStream == null) {
            return "";
        }
        Intrinsics.checkNotNullExpressionValue(errorStream, "");
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(errorStream, Charsets.UTF_8), 8192);
        Intrinsics.checkNotNullParameter(bufferedReader, "<this>");
        ArrayList arrayList = new ArrayList();
        kotlin.io.m action = new kotlin.io.m(arrayList);
        Intrinsics.checkNotNullParameter(bufferedReader, "<this>");
        Intrinsics.checkNotNullParameter(action, "action");
        try {
            Intrinsics.checkNotNullParameter(bufferedReader, "<this>");
            C4931w c4931w = new C4931w(bufferedReader);
            Intrinsics.checkNotNullParameter(c4931w, "<this>");
            Iterator it2 = new kotlin.sequences.a(c4931w).iterator();
            while (it2.hasNext()) {
                action.invoke(it2.next());
            }
            Unit unit = Unit.a;
            bufferedReader.close();
            String strS = CollectionsKt.S(arrayList, null, null, null, null, 63);
            bufferedReader.close();
            return strS == null ? "" : strS;
        } catch (Throwable th2) {
            try {
                throw th2;
            } catch (Throwable th3) {
                AbstractC3336f.c(bufferedReader, th2);
                throw th3;
            }
        }
    }

    @NotNull
    public abstract String getCurrencyIso4217Code();

    @NotNull
    public abstract String getCurrencyIso4217Code(@NotNull String str);

    public boolean getMediationNetwork() {
        return this.getRevenue;
    }

    public final boolean getMonetizationNetwork() {
        HttpURLConnection httpURLConnection;
        long jCurrentTimeMillis = System.currentTimeMillis();
        HttpURLConnection httpURLConnection2 = null;
        try {
            String currencyIso4217Code = getCurrencyIso4217Code();
            Intrinsics.checkNotNullParameter(currencyIso4217Code, "");
            URLConnection uRLConnection = (URLConnection) FirebasePerfUrlConnection.instrument(new URL(currencyIso4217Code).openConnection());
            Intrinsics.e(uRLConnection, "");
            httpURLConnection = (HttpURLConnection) uRLConnection;
        } catch (Throwable th) {
            th = th;
        }
        try {
            boolean monetizationNetwork = getMonetizationNetwork(httpURLConnection, jCurrentTimeMillis);
            httpURLConnection.disconnect();
            return monetizationNetwork;
        } catch (Throwable th2) {
            th = th2;
            httpURLConnection2 = httpURLConnection;
            try {
                String str = "error: " + th + "\n\ttook " + (System.currentTimeMillis() - jCurrentTimeMillis) + "ms\n\t" + th.getMessage();
                String currencyIso4217Code2 = getCurrencyIso4217Code("HTTP: [" + (httpURLConnection2 != null ? httpURLConnection2.hashCode() : 0) + "] " + str);
                if (getMediationNetwork()) {
                    AFLogger.afRDLog(currencyIso4217Code2);
                } else {
                    AFLogger.afVerboseLog(currencyIso4217Code2);
                }
                if (httpURLConnection2 != null) {
                    httpURLConnection2.disconnect();
                }
                return false;
            } catch (Throwable th3) {
                if (httpURLConnection2 != null) {
                    httpURLConnection2.disconnect();
                }
                throw th3;
            }
        }
    }

    @NotNull
    public abstract AFd1gSDK getRevenue();

    private final boolean getMonetizationNetwork(HttpURLConnection httpURLConnection, long j) throws IOException {
        httpURLConnection.setRequestMethod("POST");
        StringBuilder sb = new StringBuilder(httpURLConnection.getRequestMethod() + ":" + httpURLConnection.getURL());
        sb.append("\n length: ");
        sb.append(new String(this.getCurrencyIso4217Code, Charsets.UTF_8).length());
        Map<String, String> map = this.getMonetizationNetwork;
        if (map != null) {
            for (Map.Entry<String, String> entry : map.entrySet()) {
                sb.append("\n ");
                sb.append(entry.getKey());
                sb.append(": ");
                sb.append(entry.getValue());
            }
        }
        String currencyIso4217Code = getCurrencyIso4217Code("HTTP: [" + httpURLConnection.hashCode() + "] " + ((Object) sb));
        if (getMediationNetwork()) {
            AFLogger.afRDLog(currencyIso4217Code);
        } else {
            AFLogger.afVerboseLog(currencyIso4217Code);
        }
        httpURLConnection.setInstanceFollowRedirects(false);
        httpURLConnection.setUseCaches(false);
        httpURLConnection.setReadTimeout(this.AFAdRevenueData);
        httpURLConnection.setConnectTimeout(this.AFAdRevenueData);
        httpURLConnection.addRequestProperty("Content-Type", getRevenue().getRevenue);
        Map<String, String> map2 = this.getMonetizationNetwork;
        if (map2 != null) {
            for (Map.Entry<String, String> entry2 : map2.entrySet()) {
                httpURLConnection.addRequestProperty(entry2.getKey(), entry2.getValue());
            }
        }
        httpURLConnection.setDoOutput(true);
        httpURLConnection.setRequestProperty("Content-Length", String.valueOf(this.getCurrencyIso4217Code.length));
        OutputStream outputStream = httpURLConnection.getOutputStream();
        Intrinsics.checkNotNullExpressionValue(outputStream, "");
        BufferedOutputStream bufferedOutputStream = outputStream instanceof BufferedOutputStream ? (BufferedOutputStream) outputStream : new BufferedOutputStream(outputStream, 8192);
        bufferedOutputStream.write(this.getCurrencyIso4217Code);
        bufferedOutputStream.close();
        String strAFAdRevenueData = AFAdRevenueData(httpURLConnection);
        long jCurrentTimeMillis = System.currentTimeMillis() - j;
        String str = "response code:" + httpURLConnection.getResponseCode() + " " + httpURLConnection.getResponseMessage() + "\n\tbody:" + strAFAdRevenueData + "\n\ttook " + jCurrentTimeMillis + "ms";
        String currencyIso4217Code2 = getCurrencyIso4217Code("HTTP: [" + httpURLConnection.hashCode() + "] " + str);
        if (getMediationNetwork()) {
            AFLogger.afRDLog(currencyIso4217Code2);
        } else {
            AFLogger.afVerboseLog(currencyIso4217Code2);
        }
        return AFd1tSDK.getRevenue(httpURLConnection);
    }
}
