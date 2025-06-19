package com.quizlet.shared.usecase.srs;

import android.content.ActivityNotFoundException;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.media.MediaExtractor;
import android.media.MediaMetadataRetriever;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.text.TextUtils;
import android.util.Log;
import androidx.camera.camera2.internal.c0;
import androidx.fragment.app.Fragment;
import androidx.profileinstaller.c;
import com.android.volley.AuthFailureError;
import com.android.volley.l;
import com.bumptech.glide.load.engine.cache.f;
import com.bumptech.glide.load.resource.bitmap.E;
import com.facebook.e;
import com.google.android.gms.ads.g;
import com.google.android.gms.ads.internal.j;
import com.google.android.gms.ads.internal.overlay.zzc;
import com.google.android.gms.ads.internal.util.A;
import com.google.android.gms.ads.internal.util.F;
import com.google.android.gms.ads.internal.util.client.i;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C2601s7;
import com.google.android.gms.internal.ads.Hk;
import com.google.android.gms.internal.measurement.C2976c3;
import com.google.android.gms.internal.measurement.E3;
import com.google.android.gms.internal.measurement.G3;
import com.google.android.gms.internal.measurement.K2;
import com.google.android.gms.internal.measurement.O2;
import com.google.android.gms.internal.measurement.Q2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3723t;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.google.android.gms.measurement.internal.AbstractC3893t;
import com.google.android.gms.measurement.internal.Z;
import com.google.android.gms.measurement.internal.r;
import com.google.android.libraries.identity.googleid.GoogleIdTokenParsingException;
import com.google.firebase.components.d;
import com.google.firebase.perf.network.FirebasePerfUrlConnection;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.quizlet.data.model.V1;
import com.quizlet.data.model.Z1;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBUser;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes3.dex */
public final class a implements b, c, E, e, com.google.android.gms.dynamite.b, r, com.google.firebase.crashlytics.internal.stacktrace.a, d, com.google.zxing.datamatrix.encoder.b, com.perimeterx.mobile_sdk.doctor_app.state.d, com.quizlet.mapper.a, com.quizlet.local.ormlite.util.c {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    public static void l(SharedPreferences sharedPreferences, boolean z, JSONArray jSONArray, JSONArray jSONArray2, boolean z2) throws JSONException {
        if (!z || !z2 || retrofit2.adapter.rxjava3.d.l(jSONArray)) {
            OTLogger.c("OneTrust", 3, "No changes in purpose toggle configurations found");
            return;
        }
        String string = sharedPreferences.getString("OTT_CONSENT_STATUS", "{}");
        String string2 = sharedPreferences.getString("OTT_INTERNAL_PURPOSE_GROUP_MAP", "{}");
        String string3 = sharedPreferences.getString("OTT_CONSENTABLE_PARENT_GROUPS", "{}");
        String string4 = sharedPreferences.getString("OTT_CONSENT_LOG_DATA", "{}");
        String string5 = sharedPreferences.getString("OT_CL_DEFAULT_PAYLOAD", "{}");
        try {
            JSONObject jSONObject = new JSONObject(string);
            JSONObject jSONObject2 = new JSONObject(string2);
            JSONArray jSONArray3 = new JSONArray(string3);
            JSONObject jSONObject3 = new JSONObject(string4);
            JSONObject jSONObject4 = new JSONObject(string5);
            for (int i = 0; i < jSONArray.length(); i++) {
                String string6 = jSONArray.getString(i);
                if (jSONObject2.has(string6)) {
                    String string7 = jSONObject2.getString(string6);
                    jSONObject2.remove(string6);
                    if (jSONObject.has(string7)) {
                        jSONObject.remove(string7);
                    }
                    for (int i2 = 0; i2 < jSONArray3.length(); i2++) {
                        if (string7.equals(jSONArray3.getString(i2))) {
                            jSONArray3.remove(i2);
                        }
                    }
                }
                n(string6, jSONObject3, jSONObject4);
            }
            for (int i3 = 0; i3 < jSONArray2.length(); i3++) {
                String string8 = jSONArray.getString(i3);
                if (jSONObject2.has(string8)) {
                    String string9 = jSONObject2.getString(string8);
                    jSONObject2.remove(string8);
                    if (jSONObject.has(string9)) {
                        jSONObject.remove(string9);
                    }
                    for (int i4 = 0; i4 < jSONArray3.length(); i4++) {
                        if (string9.equals(jSONArray3.getString(i4))) {
                            jSONArray3.remove(i4);
                        }
                    }
                }
                o(jSONObject3, string8);
            }
            SharedPreferences.Editor editorEdit = sharedPreferences.edit();
            editorEdit.putString("OTT_CONSENT_STATUS", jSONObject.toString());
            editorEdit.putString("OTT_INTERNAL_PURPOSE_GROUP_MAP", jSONObject2.toString());
            editorEdit.putString("OTT_PARENT_GROUPS", jSONArray3.toString());
            editorEdit.putString("OTT_CONSENT_LOG_DATA", jSONObject3.toString());
            editorEdit.putString("OT_CL_DEFAULT_PAYLOAD", jSONObject4.toString());
            editorEdit.apply();
        } catch (JSONException e) {
            Z.o("exception while removing no toggle purposes from saved Data ", e, "OneTrust");
        }
    }

    public static void n(String str, JSONObject jSONObject, JSONObject jSONObject2) throws JSONException {
        try {
            JSONArray jSONArray = new JSONArray();
            JSONArray jSONArray2 = new JSONArray();
            if (jSONObject.has("consentPayload")) {
                jSONArray = jSONObject.getJSONObject("consentPayload").getJSONArray("purposes");
            }
            if (jSONObject2.has("consentPayload")) {
                jSONArray2 = jSONObject2.getJSONObject("consentPayload").getJSONArray("purposes");
            }
            for (int i = 0; i < jSONArray.length(); i++) {
                Locale locale = Locale.ENGLISH;
                if (str.toLowerCase(locale).equals(jSONArray.getJSONObject(i).getString("Id").toLowerCase(locale))) {
                    jSONArray.remove(i);
                }
                if (str.toLowerCase(locale).equals(jSONArray2.getJSONObject(i).getString("Id").toLowerCase(locale))) {
                    jSONArray2.remove(i);
                }
            }
        } catch (JSONException e) {
            Z.o("exception while removing no toggle purposes from saved Consent data", e, "OneTrust");
        }
    }

    public static void o(JSONObject jSONObject, String str) throws JSONException {
        try {
            JSONArray jSONArray = new JSONArray();
            if (jSONObject.has("consentPayload")) {
                jSONArray = jSONObject.getJSONObject("consentPayload").getJSONArray("purposes");
            }
            for (int i = 0; i < jSONArray.length(); i++) {
                if (str.equalsIgnoreCase(jSONArray.getJSONObject(i).getString("Id"))) {
                    jSONArray.getJSONObject(i).put("TransactionType", "OPT_OUT");
                }
            }
        } catch (JSONException e) {
            Z.o("exception while changing no  LI toggle purposes from saved Consent data", e, "OneTrust");
        }
    }

    public static boolean p(String str) {
        return "IAB2".equalsIgnoreCase(str) || "IAB2V2".equalsIgnoreCase(str);
    }

    public static boolean q(JSONObject jSONObject, boolean z) {
        if (jSONObject.optBoolean("IsIabPurpose") && jSONObject.optString("Status", "").contains("always")) {
            return true;
        }
        return !z ? jSONObject.optBoolean("HasConsentOptOut") : jSONObject.optBoolean("HasConsentOptOut") || jSONObject.optBoolean("HasLegIntOptOut");
    }

    public static void r(HttpURLConnection httpURLConnection, l lVar, byte[] bArr) throws IOException {
        httpURLConnection.setDoOutput(true);
        if (!httpURLConnection.getRequestProperties().containsKey("Content-Type")) {
            httpURLConnection.setRequestProperty("Content-Type", lVar.getBodyContentType());
        }
        DataOutputStream dataOutputStream = new DataOutputStream(httpURLConnection.getOutputStream());
        dataOutputStream.write(bArr);
        dataOutputStream.close();
    }

    public static ArrayList s(Map map) {
        ArrayList arrayList = new ArrayList(map.size());
        for (Map.Entry entry : map.entrySet()) {
            if (entry.getKey() != null) {
                Iterator it2 = ((List) entry.getValue()).iterator();
                while (it2.hasNext()) {
                    arrayList.add(new com.android.volley.e((String) entry.getKey(), (String) it2.next()));
                }
            }
        }
        return arrayList;
    }

    /* JADX WARN: Removed duplicated region for block: B:4:0x0011  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.quizlet.features.settings.data.states.h w(com.quizlet.features.settings.data.models.a r6) {
        /*
            java.lang.String r0 = "input"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r0)
            java.lang.String r0 = r6.a
            boolean r1 = kotlin.text.StringsKt.O(r0)
            r2 = 0
            r3 = 0
            java.lang.String r4 = "args"
            if (r1 == 0) goto L13
        L11:
            r1 = r2
            goto L4f
        L13:
            java.lang.String r1 = r6.c
            if (r1 == 0) goto L36
            boolean r5 = kotlin.text.StringsKt.O(r1)
            if (r5 == 0) goto L1e
            goto L36
        L1e:
            boolean r1 = r0.equals(r1)
            if (r1 == 0) goto L36
            java.lang.Object[] r0 = new java.lang.Object[r3]
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r4)
            com.quizlet.qutils.string.f r1 = new com.quizlet.qutils.string.f
            java.util.List r0 = kotlin.collections.C4933y.P(r0)
            r5 = 2132019211(0x7f14080b, float:1.967675E38)
            r1.<init>(r5, r0)
            goto L4f
        L36:
            int r0 = r0.length()
            r1 = 8
            if (r0 >= r1) goto L11
            java.lang.Object[] r0 = new java.lang.Object[r3]
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r4)
            com.quizlet.qutils.string.f r1 = new com.quizlet.qutils.string.f
            java.util.List r0 = kotlin.collections.C4933y.P(r0)
            r5 = 2132019213(0x7f14080d, float:1.9676755E38)
            r1.<init>(r5, r0)
        L4f:
            java.lang.String r0 = r6.b
            boolean r5 = kotlin.text.StringsKt.O(r0)
            if (r5 == 0) goto L59
        L57:
            r0 = r2
            goto L72
        L59:
            java.lang.String r6 = r6.a
            boolean r6 = kotlin.jvm.internal.Intrinsics.b(r6, r0)
            if (r6 != 0) goto L57
            java.lang.Object[] r6 = new java.lang.Object[r3]
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r6, r4)
            com.quizlet.qutils.string.f r0 = new com.quizlet.qutils.string.f
            java.util.List r6 = kotlin.collections.C4933y.P(r6)
            r3 = 2132019210(0x7f14080a, float:1.9676748E38)
            r0.<init>(r3, r6)
        L72:
            if (r1 != 0) goto L7a
            if (r0 == 0) goto L77
            goto L7a
        L77:
            com.quizlet.features.settings.data.states.f r6 = com.quizlet.features.settings.data.states.f.a
            return r6
        L7a:
            com.quizlet.features.settings.data.states.e r6 = new com.quizlet.features.settings.data.states.e
            r3 = 4
            r6.<init>(r1, r0, r2, r3)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.shared.usecase.srs.a.w(com.quizlet.features.settings.data.models.a):com.quizlet.features.settings.data.states.h");
    }

    public static void x(HttpURLConnection httpURLConnection, l lVar) throws IOException, AuthFailureError {
        switch (lVar.getMethod()) {
            case -1:
                byte[] postBody = lVar.getPostBody();
                if (postBody != null) {
                    httpURLConnection.setRequestMethod("POST");
                    r(httpURLConnection, lVar, postBody);
                    return;
                }
                return;
            case 0:
                httpURLConnection.setRequestMethod("GET");
                return;
            case 1:
                httpURLConnection.setRequestMethod("POST");
                byte[] body = lVar.getBody();
                if (body != null) {
                    r(httpURLConnection, lVar, body);
                    return;
                }
                return;
            case 2:
                httpURLConnection.setRequestMethod("PUT");
                byte[] body2 = lVar.getBody();
                if (body2 != null) {
                    r(httpURLConnection, lVar, body2);
                    return;
                }
                return;
            case 3:
                httpURLConnection.setRequestMethod("DELETE");
                return;
            case 4:
                httpURLConnection.setRequestMethod("HEAD");
                return;
            case 5:
                httpURLConnection.setRequestMethod("OPTIONS");
                return;
            case 6:
                httpURLConnection.setRequestMethod("TRACE");
                return;
            case 7:
                httpURLConnection.setRequestMethod("PATCH");
                byte[] body3 = lVar.getBody();
                if (body3 != null) {
                    r(httpURLConnection, lVar, body3);
                    return;
                }
                return;
            default:
                throw new IllegalStateException("Unknown method type.");
        }
    }

    public static final boolean y(Context context, Intent intent, com.google.android.gms.ads.internal.overlay.c cVar, com.google.android.gms.ads.internal.overlay.a aVar, boolean z, Hk hk, String str) {
        int iD;
        if (z) {
            Uri data = intent.getData();
            try {
                j.C.c.getClass();
                iD = F.D(context, data);
                if (cVar != null) {
                    cVar.h();
                }
            } catch (ActivityNotFoundException e) {
                i.h(e.getMessage());
                iD = 6;
            }
            if (aVar != null) {
                aVar.F(iD);
            }
            return iD == 5;
        }
        try {
            A.l("Launching an intent: " + intent.toURI());
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Zc)).booleanValue()) {
                F f = j.C.c;
                F.s(context, intent, hk, str);
            } else {
                F f2 = j.C.c;
                F.q(context, intent);
            }
            if (cVar != null) {
                cVar.h();
            }
            if (aVar != null) {
                aVar.V(true);
            }
            return true;
        } catch (ActivityNotFoundException e2) {
            i.h(e2.getMessage());
            if (aVar != null) {
                aVar.V(false);
            }
            return false;
        }
    }

    public static final boolean z(Context context, zzc zzcVar, com.google.android.gms.ads.internal.overlay.c cVar, com.google.android.gms.ads.internal.overlay.a aVar, Hk hk, String str) {
        int i = 0;
        if (zzcVar == null) {
            i.h("No intent data for launcher overlay.");
            return false;
        }
        AbstractC2773w7.a(context);
        Intent intent = zzcVar.h;
        if (intent != null) {
            return y(context, intent, cVar, aVar, zzcVar.j, hk, str);
        }
        Intent intent2 = new Intent();
        String str2 = zzcVar.b;
        if (TextUtils.isEmpty(str2)) {
            i.h("Open GMSG did not contain a URL.");
            return false;
        }
        String str3 = zzcVar.c;
        if (TextUtils.isEmpty(str3)) {
            intent2.setData(Uri.parse(str2));
        } else {
            intent2.setDataAndType(Uri.parse(str2), str3);
        }
        intent2.setAction("android.intent.action.VIEW");
        String str4 = zzcVar.d;
        if (!TextUtils.isEmpty(str4)) {
            intent2.setPackage(str4);
        }
        String str5 = zzcVar.e;
        if (!TextUtils.isEmpty(str5)) {
            String[] strArrSplit = str5.split("/", 2);
            if (strArrSplit.length < 2) {
                i.h("Could not parse component name from open GMSG: ".concat(str5));
                return false;
            }
            intent2.setClassName(strArrSplit[0], strArrSplit[1]);
        }
        String str6 = zzcVar.f;
        if (!TextUtils.isEmpty(str6)) {
            try {
                i = Integer.parseInt(str6);
            } catch (NumberFormatException unused) {
                i.h("Could not parse intent flags.");
            }
            intent2.addFlags(i);
        }
        C2601s7 c2601s7 = AbstractC2773w7.B4;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            intent2.addFlags(268435456);
            intent2.putExtra("android.support.customtabs.extra.user_opt_out", true);
        } else {
            if (((Boolean) rVar.c.a(AbstractC2773w7.A4)).booleanValue()) {
                F f = j.C.c;
                F.F(context, intent2);
            }
        }
        return y(context, intent2, cVar, aVar, zzcVar.j, hk, str);
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public com.perimeterx.mobile_sdk.doctor_app.state.a a() {
        return null;
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public com.perimeterx.mobile_sdk.doctor_app.state.a b() {
        return null;
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public Fragment c() {
        return new com.perimeterx.mobile_sdk.doctor_app.ui.j();
    }

    @Override // com.perimeterx.mobile_sdk.doctor_app.state.d
    public ArrayList d() {
        return new ArrayList();
    }

    @Override // com.google.firebase.crashlytics.internal.stacktrace.a
    public StackTraceElement[] e(StackTraceElement[] stackTraceElementArr) {
        if (stackTraceElementArr.length <= 1024) {
            return stackTraceElementArr;
        }
        StackTraceElement[] stackTraceElementArr2 = new StackTraceElement[1024];
        System.arraycopy(stackTraceElementArr, 0, stackTraceElementArr2, 0, g.MAX_CONTENT_URL_LENGTH);
        System.arraycopy(stackTraceElementArr, stackTraceElementArr.length - g.MAX_CONTENT_URL_LENGTH, stackTraceElementArr2, g.MAX_CONTENT_URL_LENGTH, g.MAX_CONTENT_URL_LENGTH);
        return stackTraceElementArr2;
    }

    @Override // com.google.firebase.components.d
    public Object f(c0 c0Var) {
        return new com.google.mlkit.common.sdkinternal.g();
    }

    @Override // com.quizlet.local.ormlite.util.c
    public ArrayList g(List list) {
        return AbstractC3771z.c(this, list);
    }

    @Override // com.quizlet.local.ormlite.util.c
    public Object h(Object obj) {
        DBStudySet local = (DBStudySet) obj;
        Intrinsics.checkNotNullParameter(local, "local");
        DBUser creator = local.getCreator();
        return new Z1(com.quizlet.local.ormlite.models.set.a.a(local), creator != null ? assistantMode.utils.studiableMetadata.b.O(creator) : null, V1.b);
    }

    @Override // com.facebook.e
    public String i() {
        return "ig_refresh_token";
    }

    @Override // com.facebook.e
    public String j() {
        return "refresh_access_token";
    }

    @Override // com.google.android.gms.dynamite.b
    public f k(Context context, String str, com.google.android.gms.dynamite.a aVar) {
        int iD;
        f fVar = new f();
        int iE = aVar.e(context, str);
        fVar.a = iE;
        int i = 1;
        int i2 = 0;
        if (iE != 0) {
            iD = aVar.d(context, str, false);
            fVar.b = iD;
        } else {
            iD = aVar.d(context, str, true);
            fVar.b = iD;
        }
        int i3 = fVar.a;
        if (i3 == 0) {
            if (iD == 0) {
                i = 0;
            }
            fVar.c = i;
            return fVar;
        }
        i2 = i3;
        if (i2 >= iD) {
            i = -1;
        }
        fVar.c = i;
        return fVar;
    }

    @Override // com.bumptech.glide.load.resource.bitmap.E
    public void m(MediaMetadataRetriever mediaMetadataRetriever, Object obj) throws IllegalArgumentException {
        mediaMetadataRetriever.setDataSource(((ParcelFileDescriptor) obj).getFileDescriptor());
    }

    public Object t(Object obj) throws GoogleIdTokenParsingException {
        Bundle data = (Bundle) obj;
        Intrinsics.checkNotNullParameter(data, "input");
        Intrinsics.checkNotNullParameter(data, "data");
        try {
            String string = data.getString("com.google.android.libraries.identity.googleid.BUNDLE_KEY_ID");
            String string2 = data.getString("com.google.android.libraries.identity.googleid.BUNDLE_KEY_ID_TOKEN");
            String string3 = data.getString("com.google.android.libraries.identity.googleid.BUNDLE_KEY_DISPLAY_NAME");
            String string4 = data.getString("com.google.android.libraries.identity.googleid.BUNDLE_KEY_FAMILY_NAME");
            String string5 = data.getString("com.google.android.libraries.identity.googleid.BUNDLE_KEY_GIVEN_NAME");
            Uri uri = Build.VERSION.SDK_INT >= 33 ? (Uri) data.getParcelable("com.google.android.libraries.identity.googleid.BUNDLE_KEY_PROFILE_PICTURE_URI", Uri.class) : (Uri) data.getParcelable("com.google.android.libraries.identity.googleid.BUNDLE_KEY_PROFILE_PICTURE_URI");
            String string6 = data.getString("com.google.android.libraries.identity.googleid.BUNDLE_KEY_PHONE_NUMBER");
            Intrinsics.d(string);
            Intrinsics.d(string2);
            return new com.google.android.libraries.identity.googleid.c(string, string2, string3, string4, string5, uri, string6);
        } catch (Exception e) {
            throw new GoogleIdTokenParsingException(e);
        }
    }

    public com.android.volley.toolbox.a u(l lVar, Map map) {
        String url = lVar.getUrl();
        HashMap map2 = new HashMap();
        map2.putAll(map);
        map2.putAll(lVar.getHeaders());
        URL url2 = new URL(url);
        HttpURLConnection httpURLConnection = (HttpURLConnection) ((URLConnection) FirebasePerfUrlConnection.instrument(url2.openConnection()));
        httpURLConnection.setInstanceFollowRedirects(HttpURLConnection.getFollowRedirects());
        int timeoutMs = lVar.getTimeoutMs();
        httpURLConnection.setConnectTimeout(timeoutMs);
        httpURLConnection.setReadTimeout(timeoutMs);
        boolean z = false;
        httpURLConnection.setUseCaches(false);
        httpURLConnection.setDoInput(true);
        "https".equals(url2.getProtocol());
        try {
            for (String str : map2.keySet()) {
                httpURLConnection.setRequestProperty(str, (String) map2.get(str));
            }
            x(httpURLConnection, lVar);
            int responseCode = httpURLConnection.getResponseCode();
            if (responseCode == -1) {
                throw new IOException("Could not retrieve response code from HttpUrlConnection.");
            }
            if (lVar.getMethod() == 4 || ((100 <= responseCode && responseCode < 200) || responseCode == 204 || responseCode == 304)) {
                com.android.volley.toolbox.a aVar = new com.android.volley.toolbox.a(responseCode, s(httpURLConnection.getHeaderFields()), -1, null);
                httpURLConnection.disconnect();
                return aVar;
            }
            try {
                return new com.android.volley.toolbox.a(responseCode, s(httpURLConnection.getHeaderFields()), httpURLConnection.getContentLength(), new com.android.volley.toolbox.e(httpURLConnection, 0));
            } catch (Throwable th) {
                th = th;
                z = true;
                if (!z) {
                    httpURLConnection.disconnect();
                }
                throw th;
            }
        } catch (Throwable th2) {
            th = th2;
        }
    }

    public io.reactivex.rxjava3.internal.operators.single.g v(androidx.work.impl.model.c userProps, Object obj) {
        com.quizlet.quizletandroid.config.features.properties.b contentProps = (com.quizlet.quizletandroid.config.features.properties.b) obj;
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        Intrinsics.checkNotNullParameter(contentProps, "contentProps");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = com.google.android.gms.dynamite.d.e(userProps.u());
        io.reactivex.rxjava3.internal.operators.single.g gVarG = contentProps.b.g(com.quizlet.quizletandroid.config.features.properties.a.b);
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        io.reactivex.rxjava3.internal.operators.single.g gVarG2 = contentProps.a.g(com.quizlet.quizletandroid.config.features.properties.a.c);
        Intrinsics.checkNotNullExpressionValue(gVarG2, "map(...)");
        io.reactivex.rxjava3.internal.operators.single.g gVarE2 = com.google.android.gms.dynamite.d.e(gVarG2);
        io.reactivex.rxjava3.internal.operators.single.g gVarG3 = contentProps.b.g(com.quizlet.quizletandroid.config.features.properties.a.e);
        Intrinsics.checkNotNullExpressionValue(gVarG3, "map(...)");
        return com.google.android.gms.dynamite.d.b(gVarE, com.google.android.gms.dynamite.d.f(gVarG, com.google.android.gms.dynamite.d.b(gVarE2, gVarG3)));
    }

    @Override // com.google.android.gms.measurement.internal.r
    public Object zza() {
        switch (this.a) {
            case 10:
                List list = AbstractC3893t.a;
                Boolean bool = (Boolean) C2976c3.b.b();
                bool.getClass();
                return bool;
            case 11:
                List list2 = AbstractC3893t.a;
                E3.b.get();
                Boolean bool2 = (Boolean) G3.h.b();
                bool2.getClass();
                return bool2;
            case 12:
                Boolean bool3 = (Boolean) K2.b.b();
                bool3.getClass();
                return bool3;
            case 13:
                List list3 = AbstractC3893t.a;
                E3.b.get();
                Boolean bool4 = (Boolean) G3.b.b();
                bool4.getClass();
                return bool4;
            case 14:
                List list4 = AbstractC3893t.a;
                O2.b.get();
                Long l = (Long) Q2.w.b();
                l.getClass();
                return l;
            case 15:
                List list5 = AbstractC3893t.a;
                O2.b.get();
                return (String) Q2.g.b();
            case 16:
                List list6 = AbstractC3893t.a;
                O2.b.get();
                return (String) Q2.Z.b();
            default:
                List list7 = AbstractC3893t.a;
                O2.b.get();
                Boolean bool5 = (Boolean) Q2.A.b();
                bool5.getClass();
                return bool5;
        }
    }

    public a(assistantMode.utils.studiableMetadata.b localUserMapper, com.quizlet.local.ormlite.models.set.a localStudySetMapper) {
        this.a = 28;
        Intrinsics.checkNotNullParameter(localUserMapper, "localUserMapper");
        Intrinsics.checkNotNullParameter(localStudySetMapper, "localStudySetMapper");
    }

    @Override // com.quizlet.mapper.a
    public /* bridge */ /* synthetic */ Object a(Object obj) {
        return w((com.quizlet.features.settings.data.models.a) obj);
    }

    @Override // androidx.profileinstaller.c
    public void b(int i, Serializable serializable) {
        String str;
        switch (i) {
            case 1:
                str = "RESULT_INSTALL_SUCCESS";
                break;
            case 2:
                str = "RESULT_ALREADY_INSTALLED";
                break;
            case 3:
                str = "RESULT_UNSUPPORTED_ART_VERSION";
                break;
            case 4:
                str = "RESULT_NOT_WRITABLE";
                break;
            case 5:
                str = "RESULT_DESIRED_FORMAT_UNSUPPORTED";
                break;
            case 6:
                str = "RESULT_BASELINE_PROFILE_NOT_FOUND";
                break;
            case 7:
                str = "RESULT_IO_EXCEPTION";
                break;
            case 8:
                str = "RESULT_PARSE_EXCEPTION";
                break;
            case 9:
            default:
                str = "";
                break;
            case 10:
                str = "RESULT_INSTALL_SKIP_FILE_SUCCESS";
                break;
            case 11:
                str = "RESULT_DELETE_SKIP_FILE_SUCCESS";
                break;
        }
        if (i == 6 || i == 7 || i == 8) {
            Log.e("ProfileInstaller", str, (Throwable) serializable);
        }
    }

    @Override // com.google.zxing.datamatrix.encoder.b
    public void c(com.google.zxing.datamatrix.encoder.c cVar) {
        StringBuilder sb = new StringBuilder();
        sb.append((char) 0);
        while (true) {
            if (!cVar.b()) {
                break;
            }
            sb.append(cVar.a());
            int i = cVar.d + 1;
            cVar.d = i;
            if (AbstractC3723t.f(cVar.a, i, 5) != 5) {
                cVar.e = 0;
                break;
            }
        }
        int length = sb.length() - 1;
        StringBuilder sb2 = cVar.c;
        int length2 = sb2.length() + length + 1;
        cVar.c(length2);
        boolean z = cVar.f.b - length2 > 0;
        if (cVar.b() || z) {
            if (length <= 249) {
                sb.setCharAt(0, (char) length);
            } else {
                if (length > 1555) {
                    throw new IllegalStateException("Message length not in valid ranges: ".concat(String.valueOf(length)));
                }
                sb.setCharAt(0, (char) ((length / 250) + 249));
                sb.insert(1, (char) (length % 250));
            }
        }
        int length3 = sb.length();
        for (int i2 = 0; i2 < length3; i2++) {
            int length4 = (((sb2.length() + 1) * 149) % 255) + 1 + sb.charAt(i2);
            if (length4 > 255) {
                length4 -= 256;
            }
            cVar.d((char) length4);
        }
    }

    @Override // com.bumptech.glide.load.resource.bitmap.E
    public void d(MediaExtractor mediaExtractor, Object obj) throws IOException {
        mediaExtractor.setDataSource(((ParcelFileDescriptor) obj).getFileDescriptor());
    }
}
