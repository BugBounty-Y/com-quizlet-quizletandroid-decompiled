package org.prebid.mobile.rendering.networking;

import android.os.AsyncTask;
import android.support.v4.media.session.a;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.firebase.perf.network.FirebasePerfUrlConnection;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLConnection;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import org.apache.http.conn.ConnectTimeoutException;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.PrebidMobile;
import org.prebid.mobile.rendering.loading.FileDownloadTask;
import org.prebid.mobile.rendering.networking.exception.BaseExceptionHolder;
import org.prebid.mobile.rendering.utils.helpers.Utils;

/* loaded from: classes3.dex */
public class BaseNetworkTask extends AsyncTask<GetUrlParams, Integer, GetUrlResult> {
    public long b;
    public BaseResponseHandler c;
    public URLConnection d = null;
    public GetUrlResult a = new GetUrlResult();

    public static class GetUrlParams {
        public String a;
        public String b;
        public String c;
        public String d;
        public String e;
    }

    public static class GetUrlResult extends BaseExceptionHolder {
        public String b;
        public int c;
        public long d;
    }

    public BaseNetworkTask(BaseResponseHandler baseResponseHandler) {
        this.c = baseResponseHandler;
    }

    /* JADX WARN: Removed duplicated region for block: B:29:0x003d  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0053  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String d(java.io.InputStream r6) throws java.lang.Throwable {
        /*
            if (r6 != 0) goto L4
            r6 = 0
            return r6
        L4:
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            r0.<init>()
            r1 = 0
            java.io.BufferedReader r2 = new java.io.BufferedReader     // Catch: java.lang.Exception -> L38
            java.io.InputStreamReader r3 = new java.io.InputStreamReader     // Catch: java.lang.Exception -> L38
            r3.<init>(r6)     // Catch: java.lang.Exception -> L38
            r2.<init>(r3)     // Catch: java.lang.Exception -> L38
            r6 = 1024(0x400, float:1.435E-42)
            char[] r3 = new char[r6]     // Catch: java.lang.Throwable -> L2e
            r4 = r1
        L19:
            int r5 = r2.read(r3, r1, r6)     // Catch: java.lang.Throwable -> L24
            if (r5 <= 0) goto L27
            r4 = 1
            r0.append(r3, r1, r5)     // Catch: java.lang.Throwable -> L24
            goto L19
        L24:
            r6 = move-exception
            r1 = r4
            goto L2f
        L27:
            r2.close()     // Catch: java.lang.Exception -> L2b
            goto L68
        L2b:
            r6 = move-exception
            r1 = r4
            goto L39
        L2e:
            r6 = move-exception
        L2f:
            r2.close()     // Catch: java.lang.Throwable -> L33
            goto L37
        L33:
            r2 = move-exception
            r6.addSuppressed(r2)     // Catch: java.lang.Exception -> L38
        L37:
            throw r6     // Catch: java.lang.Exception -> L38
        L38:
            r6 = move-exception
        L39:
            java.lang.String r2 = "BaseNetworkTask"
            if (r1 == 0) goto L53
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            java.lang.String r3 = "Exception in readResponse(): "
            r1.<init>(r3)
            java.lang.String r6 = r6.getMessage()
            r1.append(r6)
            java.lang.String r6 = r1.toString()
            org.prebid.mobile.LogUtil.b(r2, r6)
            goto L68
        L53:
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            java.lang.String r3 = "Empty response: "
            r1.<init>(r3)
            java.lang.String r6 = r6.getMessage()
            r1.append(r6)
            java.lang.String r6 = r1.toString()
            org.prebid.mobile.LogUtil.b(r2, r6)
        L68:
            java.lang.String r6 = r0.toString()
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: org.prebid.mobile.rendering.networking.BaseNetworkTask.d(java.io.InputStream):java.lang.String");
    }

    public GetUrlResult a(int i, URLConnection uRLConnection) {
        return this.a;
    }

    public final void b() {
        this.c = null;
        URLConnection uRLConnection = this.d;
        if (uRLConnection instanceof HttpURLConnection) {
            ((HttpURLConnection) uRLConnection).disconnect();
        }
    }

    @Override // android.os.AsyncTask
    /* renamed from: c */
    public void onPostExecute(GetUrlResult getUrlResult) {
        if (getUrlResult == null) {
            LogUtil.e(3, "BaseNetworkTask", "URL result is null");
            b();
            return;
        }
        if (this.c == null) {
            LogUtil.e(3, "BaseNetworkTask", "No ResponseHandler on: may be a tracking event");
            b();
            return;
        }
        LogUtil.e(3, "BaseNetworkTask", "Result: " + getUrlResult.b);
        getUrlResult.d = System.currentTimeMillis() - this.b;
        Exception exc = getUrlResult.a;
        if (exc != null) {
            ((ResponseHandler) this.c).a(exc);
            b();
            return;
        }
        String str = getUrlResult.b;
        if (str == null || str.length() >= 100 || !getUrlResult.b.contains("<VAST")) {
            ((ResponseHandler) this.c).b(getUrlResult);
        } else {
            ((ResponseHandler) this.c).c("Invalid VAST Response: less than 100 characters.");
        }
        b();
    }

    @Override // android.os.AsyncTask
    public final GetUrlResult doInBackground(GetUrlParams[] getUrlParamsArr) {
        URLConnection uRLConnection;
        GetUrlParams[] getUrlParamsArr2 = getUrlParamsArr;
        if (isCancelled()) {
            return this.a;
        }
        if (getUrlParamsArr2 != null && getUrlParamsArr2[0] != null) {
            if (!isCancelled()) {
                GetUrlParams getUrlParams = getUrlParamsArr2[0];
                try {
                    try {
                        try {
                            try {
                                try {
                                    this.b = System.currentTimeMillis();
                                    this.a = e(getUrlParams);
                                    uRLConnection = this.d;
                                } catch (Exception e) {
                                    LogUtil.e(5, "BaseNetworkTask", "Network Error: Exception" + e.getMessage());
                                    this.a.a = e;
                                    uRLConnection = this.d;
                                    if (uRLConnection instanceof HttpURLConnection) {
                                    }
                                }
                            } catch (MalformedURLException e2) {
                                LogUtil.e(5, "BaseNetworkTask", "Network Error: MalformedURLException" + e2.getMessage());
                                this.a.a = e2;
                                uRLConnection = this.d;
                                if (uRLConnection instanceof HttpURLConnection) {
                                }
                            }
                        } catch (SocketTimeoutException e3) {
                            LogUtil.e(5, "BaseNetworkTask", "Network Error: SocketTimeoutException" + e3.getMessage());
                            this.a.a = e3;
                            uRLConnection = this.d;
                            if (uRLConnection instanceof HttpURLConnection) {
                            }
                        }
                    } catch (ConnectTimeoutException e4) {
                        LogUtil.e(5, "BaseNetworkTask", "Network Error: ConnectTimeoutException" + e4.getMessage());
                        this.a.a = e4;
                        uRLConnection = this.d;
                        if (uRLConnection instanceof HttpURLConnection) {
                        }
                    } catch (IOException e5) {
                        LogUtil.e(5, "BaseNetworkTask", "Network Error: IOException" + e5.getMessage());
                        this.a.a = e5;
                        uRLConnection = this.d;
                        if (uRLConnection instanceof HttpURLConnection) {
                        }
                    }
                    if (uRLConnection instanceof HttpURLConnection) {
                        ((HttpURLConnection) uRLConnection).disconnect();
                    }
                } catch (Throwable th) {
                    URLConnection uRLConnection2 = this.d;
                    if (uRLConnection2 instanceof HttpURLConnection) {
                        ((HttpURLConnection) uRLConnection2).disconnect();
                    }
                    throw th;
                }
            }
            return this.a;
        }
        this.a.a = new Exception("Invalid Params");
        this.a = null;
        return this.a;
    }

    public final GetUrlResult e(GetUrlParams getUrlParams) throws Exception {
        boolean z;
        if (getUrlParams.a.isEmpty()) {
            LogUtil.b("BaseNetworkTask", "url is empty. Set url in PrebidMobile (PrebidRenderingSettings).");
        }
        LogUtil.e(3, "BaseNetworkTask", "url: " + getUrlParams.a);
        LogUtil.e(3, "BaseNetworkTask", "queryParams: " + getUrlParams.b);
        URLConnection uRLConnection = (URLConnection) FirebasePerfUrlConnection.instrument(new URL(a.t(new StringBuilder(), getUrlParams.a, (!getUrlParams.e.equals("GET") || getUrlParams.b == null) ? "" : "?" + getUrlParams.b)).openConnection());
        this.d = uRLConnection;
        if (uRLConnection instanceof HttpURLConnection) {
            ((HttpURLConnection) uRLConnection).setRequestMethod(getUrlParams.e);
            ((HttpURLConnection) this.d).setInstanceFollowRedirects(false);
        }
        this.d.setRequestProperty("User-Agent", getUrlParams.d);
        this.d.setRequestProperty("Accept-Language", Locale.getDefault().toString());
        this.d.setRequestProperty("Accept", "application/x-www-form-urlencoded,application/json,text/plain,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        this.d.setRequestProperty("Content-Type", "application/json");
        URLConnection uRLConnection2 = this.d;
        HashMap map = PrebidMobile.e;
        if (!map.isEmpty()) {
            for (Map.Entry entry : map.entrySet()) {
                uRLConnection2.setRequestProperty((String) entry.getKey(), (String) entry.getValue());
            }
        }
        this.d.setConnectTimeout(PrebidMobile.a);
        if (!(this instanceof FileDownloadTask)) {
            this.d.setReadTimeout(3000);
        }
        DataOutputStream dataOutputStream = null;
        if ("POST".equals(getUrlParams.e)) {
            this.d.setDoOutput(true);
            try {
                DataOutputStream dataOutputStream2 = new DataOutputStream(this.d.getOutputStream());
                try {
                    String str = getUrlParams.b;
                    if (str != null) {
                        for (byte b : str.getBytes()) {
                            dataOutputStream2.write(b);
                        }
                    }
                    dataOutputStream2.flush();
                    dataOutputStream2.close();
                } catch (Throwable th) {
                    th = th;
                    dataOutputStream = dataOutputStream2;
                    if (dataOutputStream != null) {
                        dataOutputStream.flush();
                        dataOutputStream.close();
                    }
                    throw th;
                }
            } catch (Throwable th2) {
                th = th2;
            }
        }
        URLConnection uRLConnection3 = this.d;
        int i = 0;
        do {
            int responseCode = uRLConnection3 instanceof HttpURLConnection ? ((HttpURLConnection) uRLConnection3).getResponseCode() : 0;
            if (responseCode < 300 || responseCode > 307 || responseCode == 306 || responseCode == 304) {
                z = false;
            } else {
                URL url = uRLConnection3.getURL();
                String headerField = uRLConnection3.getHeaderField("Location");
                LogUtil.e(3, "BaseNetworkTask", headerField == null ? "not found location" : "location = ".concat(headerField));
                URL url2 = headerField != null ? new URL(url, headerField) : null;
                ((HttpURLConnection) uRLConnection3).disconnect();
                if (url2 == null || (!(url2.getProtocol().equals("http") || url2.getProtocol().equals("https")) || i >= 5)) {
                    String str2 = "Bad server response - [HTTP Response code of " + responseCode + "]";
                    LogUtil.b("BaseNetworkTask", str2);
                    throw new Exception(str2);
                }
                uRLConnection3 = (URLConnection) FirebasePerfUrlConnection.instrument(url2.openConnection());
                i++;
                z = true;
            }
        } while (z);
        this.d = uRLConnection3;
        int responseCode2 = uRLConnection3 instanceof HttpURLConnection ? ((HttpURLConnection) uRLConnection3).getResponseCode() : 0;
        if (Utils.c(getUrlParams.c) && !"DownloadTask".equals(getUrlParams.c) && !"RedirectTask".equals(getUrlParams.c) && !"StatusTask".equals(getUrlParams.c)) {
            if (responseCode2 != 200) {
                if (responseCode2 >= 400 && responseCode2 < 600) {
                    String str3 = String.format(Locale.getDefault(), "Code %d. %s", Integer.valueOf(responseCode2), d(((HttpURLConnection) this.d).getErrorStream()));
                    LogUtil.b("BaseNetworkTask", str3);
                    throw new Exception(str3);
                }
                String strC = AbstractC0147y.c(responseCode2, "Bad server response - [HTTP Response code of ", "]");
                if (responseCode2 == 204) {
                    strC = "Response code 204. No bids.";
                }
                LogUtil.b("BaseNetworkTask", strC);
                throw new Exception(strC);
            }
            String strD = d(this.d.getInputStream());
            GetUrlResult getUrlResult = this.a;
            getUrlResult.b = strD;
            this.a = getUrlResult;
        }
        GetUrlResult getUrlResultA = a(responseCode2, this.d);
        this.a = getUrlResultA;
        getUrlResultA.c = responseCode2;
        return getUrlResultA;
    }

    @Override // android.os.AsyncTask
    public final void onCancelled(GetUrlResult getUrlResult) {
        super.onCancelled(getUrlResult);
        LogUtil.e(3, "BaseNetworkTask", "Request cancelled. Disconnecting connection");
        b();
    }

    @Override // android.os.AsyncTask
    public final void onProgressUpdate(Integer[] numArr) {
        super.onProgressUpdate(numArr);
    }
}
