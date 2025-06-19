package org.prebid.mobile.http;

import android.os.Looper;
import com.google.firebase.perf.network.FirebasePerfUrlConnection;
import com.pubmatic.sdk.video.player.s;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLConnection;
import org.prebid.mobile.tasksmanager.TasksManager;

/* loaded from: classes3.dex */
public abstract class HTTPGet {
    public static HttpURLConnection a(URL url) throws ProtocolException {
        HttpURLConnection httpURLConnection = (HttpURLConnection) ((URLConnection) FirebasePerfUrlConnection.instrument(url.openConnection()));
        httpURLConnection.setDoOutput(false);
        httpURLConnection.setDoInput(true);
        httpURLConnection.setUseCaches(false);
        httpURLConnection.setRequestMethod("GET");
        return httpURLConnection;
    }

    public final void b() {
        if (Looper.myLooper() != Looper.getMainLooper()) {
            e(d());
            return;
        }
        TasksManager tasksManagerA = TasksManager.a();
        tasksManagerA.a.execute(new Runnable() { // from class: org.prebid.mobile.http.HTTPGet.1
            @Override // java.lang.Runnable
            public final void run() {
                HTTPGet hTTPGet = HTTPGet.this;
                hTTPGet.e(hTTPGet.d());
            }
        });
    }

    public abstract String c();

    public final HTTPResponse d() throws IOException {
        HTTPResponse hTTPResponse = new HTTPResponse();
        try {
            URL url = new URL(c());
            if (url.getHost() == null) {
                hTTPResponse.a = false;
                return hTTPResponse;
            }
            HttpURLConnection httpURLConnectionA = a(url);
            httpURLConnectionA.setConnectTimeout(s.MAX_STALLING_TIMEOUT);
            httpURLConnectionA.setReadTimeout(20000);
            httpURLConnectionA.connect();
            InputStream inputStream = httpURLConnectionA.getInputStream();
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream, "utf-8"));
            while (bufferedReader.readLine() != null) {
            }
            bufferedReader.close();
            inputStream.close();
            httpURLConnectionA.getHeaderFields();
            hTTPResponse.a = httpURLConnectionA.getResponseCode() == 200;
            return hTTPResponse;
        } catch (MalformedURLException unused) {
            hTTPResponse.a = false;
            hTTPResponse.b = HttpErrorCode.b;
            return hTTPResponse;
        } catch (IOException unused2) {
            hTTPResponse.a = false;
            hTTPResponse.b = HttpErrorCode.c;
            return hTTPResponse;
        } catch (Exception e) {
            hTTPResponse.a = false;
            hTTPResponse.b = HttpErrorCode.d;
            e.printStackTrace();
            return hTTPResponse;
        }
    }

    public abstract void e(HTTPResponse hTTPResponse);
}
