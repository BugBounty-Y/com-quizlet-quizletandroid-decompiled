package com.comscore;

import com.comscore.Configuration;
import com.comscore.util.CrossPublisherIdUtil;
import com.comscore.util.setup.Setup;
import com.google.firebase.perf.network.FirebasePerfUrlConnection;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public class Activation {
    private static final String a = "https://segment-data-us-east.zqtk.net/%s?url=%s&c2=%s&c12=%s&ns_ap_bi=%s&ns_ap_sv=%s&ns_ap_an=%s&ns_ap_ver=%s&ns_ap_pn=android";
    private static final String b = "\\{\\s*\".*\"\\s*:\\s*[^\\}]*\\s*\\}";
    private static final Integer c = 60000;
    private static final Integer d = 60000;

    public interface ActivationListener {
        void onReceivedCategories(List<String> list);
    }

    public class a implements CrossPublisherIdUtil.Listener {
        final /* synthetic */ String a;
        final /* synthetic */ String b;
        final /* synthetic */ String c;
        final /* synthetic */ String d;
        final /* synthetic */ ActivationListener e;

        /* renamed from: com.comscore.Activation$a$a, reason: collision with other inner class name */
        public class RunnableC0002a implements Runnable {
            final /* synthetic */ String a;

            public RunnableC0002a(String str) {
                this.a = str;
            }

            @Override // java.lang.Runnable
            public void run() throws JSONException, UnsupportedEncodingException {
                a aVar = a.this;
                a.this.e.onReceivedCategories(Activation.a(aVar.a, aVar.b, aVar.c, aVar.d, this.a));
            }
        }

        public a(String str, String str2, String str3, String str4, ActivationListener activationListener) {
            this.a = str;
            this.b = str2;
            this.c = str3;
            this.d = str4;
            this.e = activationListener;
        }

        @Override // com.comscore.util.CrossPublisherIdUtil.Listener
        public void onCrossPublisherIdRequested(String str, boolean z) {
            new Thread(new RunnableC0002a(str)).start();
        }
    }

    public class b implements Configuration.ConfigurationListener {
        final /* synthetic */ String a;
        final /* synthetic */ String b;
        final /* synthetic */ String c;
        final /* synthetic */ String d;
        final /* synthetic */ ActivationListener e;

        public b(String str, String str2, String str3, String str4, ActivationListener activationListener) {
            this.a = str;
            this.b = str2;
            this.c = str3;
            this.d = str4;
            this.e = activationListener;
        }

        @Override // com.comscore.Configuration.ConfigurationListener
        public void onConfigurationChanged(int i) {
            if (i != 20307) {
                return;
            }
            Activation.a(this.a, this.b, this.c, this.d, this.e);
            Analytics.getConfiguration().b(this);
        }
    }

    private Activation() {
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static List<String> a(String str, String str2, String str3, String str4, String str5) throws JSONException, UnsupportedEncodingException {
        int i;
        JSONArray jSONArray;
        if (!Setup.isSetUpFinished() || str3 == null || str4 == null) {
            return new ArrayList();
        }
        String applicationId = Setup.getJniComScoreHelper().getApplicationId();
        String version = Analytics.getVersion();
        String applicationName = Setup.getJniComScoreHelper().getApplicationName();
        String applicationVersion = Setup.getJniComScoreHelper().getApplicationVersion();
        if (applicationId == null || version == null || applicationName == null || applicationVersion == null || str3.isEmpty() || str4.isEmpty() || applicationId.isEmpty() || version.isEmpty() || applicationName.isEmpty() || applicationVersion.isEmpty()) {
            return new ArrayList();
        }
        try {
            String str6 = "https://segment-data-us-east.zqtk.net/" + URLEncoder.encode(str, "UTF-8") + "?url=" + URLEncoder.encode(str2, "UTF-8") + "&c2=" + URLEncoder.encode(str3, "UTF-8") + "&c12=" + URLEncoder.encode(str4, "UTF-8") + "&ns_ap_bi=" + URLEncoder.encode(applicationId, "UTF-8") + "&ns_ap_sv=" + URLEncoder.encode(version, "UTF-8") + "&ns_ap_an=" + URLEncoder.encode(applicationName, "UTF-8") + "&ns_ap_ver=" + URLEncoder.encode(applicationVersion, "UTF-8") + "&ns_ap_pn=android";
            if (str5 != null && !str5.isEmpty()) {
                str6 = str6 + "&ns_ak=" + URLEncoder.encode(str5, "UTF-8");
            }
            try {
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                HttpURLConnection httpURLConnection = (HttpURLConnection) ((URLConnection) FirebasePerfUrlConnection.instrument(new URL(str6).openConnection()));
                httpURLConnection.setConnectTimeout(c.intValue());
                httpURLConnection.setReadTimeout(d.intValue());
                try {
                    BufferedInputStream bufferedInputStream = new BufferedInputStream(httpURLConnection.getInputStream());
                    byte[] bArr = new byte[1024];
                    while (true) {
                        int i2 = bufferedInputStream.read(bArr);
                        if (i2 == -1) {
                            break;
                        }
                        byteArrayOutputStream.write(bArr, 0, i2);
                    }
                    httpURLConnection.disconnect();
                    Matcher matcher = Pattern.compile(b).matcher(byteArrayOutputStream.toString("UTF-8"));
                    if (!matcher.find()) {
                        return new ArrayList();
                    }
                    try {
                        JSONObject jSONObject = new JSONObject(matcher.group(0));
                        try {
                            jSONArray = jSONObject.getJSONArray("data");
                        } catch (JSONException unused) {
                            jSONArray = jSONObject.getJSONArray("errors");
                        }
                        ArrayList arrayList = new ArrayList();
                        int length = jSONArray.length();
                        for (i = 0; i < length; i++) {
                            arrayList.add(jSONArray.optString(i));
                        }
                        return arrayList;
                    } catch (JSONException unused2) {
                        return new ArrayList();
                    }
                } catch (Throwable th) {
                    httpURLConnection.disconnect();
                    byteArrayOutputStream.toString("UTF-8");
                    throw th;
                }
            } catch (IOException unused3) {
                return new ArrayList();
            }
        } catch (UnsupportedEncodingException unused4) {
            return new ArrayList();
        }
    }

    public static void a(String str, String str2, String str3, String str4, ActivationListener activationListener) {
        if (Analytics.getConfiguration().d()) {
            CrossPublisherIdUtil.requestCrossPublisherId(new a(str, str2, str3, str4, activationListener));
        } else {
            Analytics.getConfiguration().a(new b(str, str2, str3, str4, activationListener));
        }
    }
}
