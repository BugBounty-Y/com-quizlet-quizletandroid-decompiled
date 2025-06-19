package org.prebid.mobile.rendering.mraid.methods.network;

import android.os.AsyncTask;
import com.google.firebase.perf.network.FirebasePerfUrlConnection;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import org.prebid.mobile.LogUtil;

/* loaded from: classes3.dex */
public class UrlResolutionTask extends AsyncTask<String, Void, String> {
    public final UrlResolutionListener a;

    public interface UrlResolutionListener {
        void a();

        void b(String str);
    }

    public UrlResolutionTask(UrlResolutionListener urlResolutionListener) {
        this.a = urlResolutionListener;
    }

    public static String a(String str) throws Throwable {
        HttpURLConnection httpURLConnection;
        HttpURLConnection httpURLConnection2 = null;
        try {
            httpURLConnection = (HttpURLConnection) ((URLConnection) FirebasePerfUrlConnection.instrument(new URL(str).openConnection()));
        } catch (Throwable th) {
            th = th;
        }
        try {
            httpURLConnection.setInstanceFollowRedirects(false);
            String strB = b(str, httpURLConnection);
            try {
                InputStream inputStream = httpURLConnection.getInputStream();
                if (inputStream != null) {
                    inputStream.close();
                }
            } catch (IOException unused) {
                LogUtil.b("UrlResolutionTask", "IOException when closing httpUrlConnection. Ignoring.");
            }
            httpURLConnection.disconnect();
            return strB;
        } catch (Throwable th2) {
            th = th2;
            httpURLConnection2 = httpURLConnection;
            if (httpURLConnection2 != null) {
                try {
                    InputStream inputStream2 = httpURLConnection2.getInputStream();
                    if (inputStream2 != null) {
                        inputStream2.close();
                    }
                } catch (IOException unused2) {
                    LogUtil.b("UrlResolutionTask", "IOException when closing httpUrlConnection. Ignoring.");
                }
                httpURLConnection2.disconnect();
            }
            throw th;
        }
    }

    public static String b(String str, HttpURLConnection httpURLConnection) throws URISyntaxException, IOException {
        URI uri = new URI(str);
        int responseCode = httpURLConnection.getResponseCode();
        String headerField = httpURLConnection.getHeaderField("location");
        if (responseCode < 300 || responseCode >= 400) {
            return null;
        }
        try {
            return uri.resolve(headerField).toString();
        } catch (IllegalArgumentException unused) {
            LogUtil.b("UrlResolutionTask", "Invalid URL redirection. baseUrl=" + str + "\n redirectUrl=" + headerField);
            throw new URISyntaxException(headerField, "Unable to parse invalid URL");
        } catch (NullPointerException e) {
            LogUtil.b("UrlResolutionTask", "Invalid URL redirection. baseUrl=" + str + "\n redirectUrl=" + headerField);
            throw e;
        }
    }

    @Override // android.os.AsyncTask
    public final String doInBackground(String[] strArr) throws Throwable {
        String[] strArr2 = strArr;
        if (strArr2 != null && strArr2.length != 0) {
            int i = 0;
            try {
                String str = null;
                for (String strA = strArr2[0]; strA != null && i < 3; strA = a(strA)) {
                    if (!strA.startsWith("http")) {
                        return strA;
                    }
                    i++;
                    str = strA;
                }
                return str;
            } catch (IOException | NullPointerException | URISyntaxException unused) {
            }
        }
        return null;
    }

    @Override // android.os.AsyncTask
    public final void onCancelled() {
        super.onCancelled();
        this.a.a();
    }

    @Override // android.os.AsyncTask
    public final void onPostExecute(String str) {
        String str2 = str;
        super.onPostExecute(str2);
        if (isCancelled() || str2 == null) {
            onCancelled();
        } else {
            this.a.b(str2);
        }
    }
}
