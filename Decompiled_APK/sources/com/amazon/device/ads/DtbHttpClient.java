package com.amazon.device.ads;

import androidx.annotation.NonNull;
import com.google.firebase.perf.network.FirebasePerfUrlConnection;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.HashMap;
import org.json.JSONException;

/* loaded from: classes.dex */
class DtbHttpClient {
    private String message;
    private int responseCode;
    private String url;
    private boolean secure = true;
    private boolean isQueryParamsEnabled = false;
    private String response = null;
    private HashMap<String, Object> params = new HashMap<>();
    private HashMap<String, Object> headers = new HashMap<>();

    public enum HTTPMethod {
        POST,
        GET
    }

    public DtbHttpClient(String str) {
        this.url = str;
    }

    @NonNull
    private static String convertStreamToString(InputStream inputStream) throws IOException {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
        StringBuilder sb = new StringBuilder();
        while (true) {
            try {
                try {
                    String line = bufferedReader.readLine();
                    if (line != null) {
                        sb.append(line + "\n");
                    }
                } catch (IOException e) {
                    DtbLog.debug("Error converting stream to string. Ex=" + e);
                }
                try {
                    break;
                } catch (IOException unused) {
                }
            } finally {
                try {
                    inputStream.close();
                } catch (IOException unused2) {
                }
            }
        }
        return sb.toString();
    }

    private HttpURLConnection createDefaultConnection(URL url, int i) throws IOException {
        HttpURLConnection httpURLConnection = (HttpURLConnection) ((URLConnection) FirebasePerfUrlConnection.instrument(url.openConnection()));
        httpURLConnection.setConnectTimeout(1000);
        httpURLConnection.setReadTimeout(i);
        return httpURLConnection;
    }

    private void executeRequest(HTTPMethod hTTPMethod, URL url, int i) throws JSONException, IOException {
        String paramsAsJsonString;
        HttpURLConnection httpURLConnectionCreateDefaultConnection = createDefaultConnection(url, i);
        StringBuilder sb = new StringBuilder();
        for (String str : this.headers.keySet()) {
            String string = this.headers.get(str) != null ? this.headers.get(str).toString() : "";
            httpURLConnectionCreateDefaultConnection.setRequestProperty(str, string);
            sb.append(str + ":" + string + " ");
        }
        DtbLog.debug("with headers:[" + ((Object) sb) + "]");
        if (hTTPMethod == HTTPMethod.POST) {
            httpURLConnectionCreateDefaultConnection.setDoOutput(true);
            if (!this.params.isEmpty()) {
                if (this.isQueryParamsEnabled) {
                    httpURLConnectionCreateDefaultConnection.setRequestProperty("content-type", "application/x-www-form-urlencoded");
                    paramsAsJsonString = getQueryParams();
                } else {
                    httpURLConnectionCreateDefaultConnection.setRequestProperty("content-type", "application/json; charset=utf-8");
                    paramsAsJsonString = getParamsAsJsonString();
                }
                DtbLog.debug("with json params:[" + paramsAsJsonString + "]");
                OutputStream outputStream = httpURLConnectionCreateDefaultConnection.getOutputStream();
                outputStream.write(paramsAsJsonString.getBytes());
                outputStream.flush();
                outputStream.close();
            }
        }
        try {
            InputStream inputStream = httpURLConnectionCreateDefaultConnection.getInputStream();
            if (inputStream == null) {
                return;
            }
            this.responseCode = httpURLConnectionCreateDefaultConnection.getResponseCode();
            this.message = httpURLConnectionCreateDefaultConnection.getResponseMessage();
            this.response = convertStreamToString(inputStream);
            inputStream.close();
            DtbLog.debug("Response :" + this.response);
        } catch (Exception e) {
            this.response = null;
            DtbLog.debug("Error while connecting to remote server: " + httpURLConnectionCreateDefaultConnection.getURL().toString() + " with error:" + e.getMessage());
        } finally {
            httpURLConnectionCreateDefaultConnection.disconnect();
        }
    }

    private String getParamsAsJsonString() throws JSONException {
        return DtbCommonUtils.getParamsAsJsonString(this.params);
    }

    private String getQueryParams() {
        String strL = "";
        if (!this.params.isEmpty()) {
            for (String str : this.params.keySet()) {
                if (this.params.get(str) != null) {
                    StringBuilder sbX = android.support.v4.media.session.a.x(str, SimpleComparison.EQUAL_TO_OPERATION);
                    sbX.append(DtbCommonUtils.getURLEncodedString(this.params.get(str).toString()));
                    String string = sbX.toString();
                    strL = strL.length() > 1 ? android.support.v4.media.session.a.l(strL, "&", string) : android.support.v4.media.session.a.k(strL, string);
                }
            }
        }
        return strL;
    }

    public void addHeader(String str, String str2) {
        this.headers.put(str, str2);
    }

    public void addParam(String str, String str2) {
        this.params.put(str, str2);
    }

    public void enableQueryParams() {
        this.isQueryParamsEnabled = true;
    }

    public void executeGET(int i) throws JSONException, IOException {
        String str;
        if (this.params.isEmpty()) {
            str = "";
        } else {
            str = "?" + getQueryParams();
        }
        String string = this.url;
        String str2 = DtbConstants.HTTPS;
        if (!string.startsWith(DtbConstants.HTTPS) && !this.url.startsWith("http://")) {
            StringBuilder sb = new StringBuilder();
            if (!this.secure) {
                str2 = "http://";
            }
            sb.append(str2);
            sb.append(this.url);
            string = sb.toString();
        }
        DtbLog.debug("GET URL:" + string);
        DtbLog.debug("with params: " + str);
        executeRequest(HTTPMethod.GET, new URL(android.support.v4.media.session.a.k(string, str)), i);
    }

    public void executePOST(int i) throws JSONException, IOException {
        StringBuilder sb = new StringBuilder();
        sb.append(this.secure ? DtbConstants.HTTPS : "http://");
        sb.append(this.url);
        String string = sb.toString();
        DtbLog.debug("POST URL:" + string);
        executeRequest(HTTPMethod.POST, new URL(string), i);
    }

    public String getErrorMessage() {
        return this.message;
    }

    public HashMap<String, Object> getHeaders() {
        return this.headers;
    }

    public HashMap<String, Object> getParams() {
        return this.params;
    }

    public String getResponse() {
        return this.response;
    }

    public int getResponseCode() {
        return this.responseCode;
    }

    public String getUrl() {
        return this.url;
    }

    public boolean isHttpStatusCodeOK() {
        return this.responseCode == 200;
    }

    public void setHeaders(HashMap<String, Object> map) {
        this.headers = map;
    }

    public void setParams(HashMap<String, Object> map) {
        this.params = map;
    }

    public void setUrl(String str) {
        this.url = str;
    }

    public void setUseSecure(boolean z) {
        this.secure = z;
    }
}
