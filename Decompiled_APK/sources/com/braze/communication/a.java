package com.braze.communication;

import java.io.BufferedInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.zip.GZIPInputStream;

/* loaded from: classes.dex */
public abstract class a {
    public static final FilterInputStream a(HttpURLConnection httpURLConnection) throws com.braze.exceptions.a, IOException {
        int i = b.b;
        httpURLConnection.connect();
        int responseCode = httpURLConnection.getResponseCode();
        if (responseCode / 100 == 2) {
            return "gzip".equalsIgnoreCase(httpURLConnection.getContentEncoding()) ? new GZIPInputStream(httpURLConnection.getInputStream()) : new BufferedInputStream(httpURLConnection.getInputStream());
        }
        StringBuilder sbV = android.support.v4.media.session.a.v(responseCode, "Bad HTTP response code from Braze: [", "] to url: ");
        sbV.append(httpURLConnection.getURL());
        throw new com.braze.exceptions.a(sbV.toString());
    }
}
