package com.comscore.util.crashreport;

import android.support.v4.media.session.a;
import com.google.firebase.perf.network.FirebasePerfUrlConnection;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

/* loaded from: classes.dex */
public class CrashReportHttpFlusher implements CrashReportFlusher {
    private static final int a = 4088;

    private HttpURLConnection a(URL url) throws IOException {
        HttpURLConnection httpURLConnection = (HttpURLConnection) ((URLConnection) FirebasePerfUrlConnection.instrument(url.openConnection()));
        httpURLConnection.setRequestProperty("Connection", "Close");
        return httpURLConnection;
    }

    public URL createURL(String str) {
        if (str.length() > a) {
            String strSubstring = str.substring(0, a);
            int iLastIndexOf = strSubstring.lastIndexOf(37);
            if (iLastIndexOf >= 4086) {
                strSubstring = strSubstring.substring(0, iLastIndexOf);
            }
            str = a.k(strSubstring, "&ns_cut=");
        }
        try {
            return new URL(str);
        } catch (MalformedURLException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override // com.comscore.util.crashreport.CrashReportFlusher
    public boolean flush(String str, CrashReportParser crashReportParser, CrashReport crashReport) throws IOException {
        boolean z = false;
        HttpURLConnection httpURLConnectionA = null;
        try {
            httpURLConnectionA = a(createURL(str + "?" + crashReportParser.reportToString(crashReport)));
            int responseCode = httpURLConnectionA.getResponseCode();
            if (responseCode == 200 || responseCode == 204) {
                z = true;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (httpURLConnectionA != null) {
            httpURLConnectionA.disconnect();
        }
        return z;
    }
}
