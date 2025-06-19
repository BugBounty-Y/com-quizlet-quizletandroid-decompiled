package com.braze.communication;

import android.net.TrafficStats;
import com.braze.support.BrazeLogger;
import com.braze.support.l;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3340g;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import kotlin.Unit;
import kotlin.collections.V;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class b {
    public static final int b = (int) TimeUnit.SECONDS.toMillis(15);
    public final int a;

    public b(int i) {
        this.a = i;
    }

    public final d a(com.braze.requests.util.c requestTarget, HashMap requestHeaders, JSONObject payload) throws IOException {
        Intrinsics.checkNotNullParameter(requestTarget, "requestTarget");
        Intrinsics.checkNotNullParameter(requestHeaders, "requestHeaders");
        Intrinsics.checkNotNullParameter(payload, "payload");
        TrafficStats.setThreadStatsTag(1337);
        URL url = requestTarget.c;
        Map mapC = V.c();
        int responseCode = -1;
        try {
            HttpURLConnection httpURLConnectionA = a(url, payload, requestHeaders);
            responseCode = httpURLConnectionA.getResponseCode();
            Map<String, List<String>> headerFields = httpURLConnectionA.getHeaderFields();
            Intrinsics.checkNotNullExpressionValue(headerFields, "getHeaderFields(...)");
            mapC = l.a(headerFields);
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(a.a(httpURLConnectionA), Charsets.UTF_8), 8192);
            try {
                String strB = AbstractC3340g.b(bufferedReader);
                bufferedReader.close();
                return new d(responseCode, mapC, new JSONObject(strB));
            } finally {
            }
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new h(requestTarget, 0), 4, (Object) null);
            return new d(responseCode, mapC, 4);
        }
    }

    public static final String a(com.braze.requests.util.c cVar) {
        return "Failed request to [" + cVar + ']';
    }

    public final HttpURLConnection a(URL url, JSONObject jSONObject, HashMap map) throws IOException {
        String string = jSONObject.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        Charset charsetForName = Charset.forName("UTF-8");
        Intrinsics.checkNotNullExpressionValue(charsetForName, "forName(...)");
        byte[] bytes = string.getBytes(charsetForName);
        Intrinsics.checkNotNullExpressionValue(bytes, "getBytes(...)");
        HttpURLConnection httpURLConnectionA = g.a.a(url);
        for (Map.Entry entry : map.entrySet()) {
            httpURLConnectionA.setRequestProperty((String) entry.getKey(), (String) entry.getValue());
        }
        httpURLConnectionA.setConnectTimeout(b);
        httpURLConnectionA.setReadTimeout(this.a);
        httpURLConnectionA.setUseCaches(false);
        httpURLConnectionA.setInstanceFollowRedirects(false);
        httpURLConnectionA.setRequestMethod("POST");
        httpURLConnectionA.setDoOutput(true);
        httpURLConnectionA.setFixedLengthStreamingMode(bytes.length);
        OutputStream outputStream = httpURLConnectionA.getOutputStream();
        try {
            outputStream.write(bytes);
            Unit unit = Unit.a;
            outputStream.close();
            return httpURLConnectionA;
        } finally {
        }
    }
}
