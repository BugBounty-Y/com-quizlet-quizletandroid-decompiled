package com.onetrust.otpublishers.headless.Internal.Network;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.camera2.internal.T;
import androidx.camera.camera2.internal.c0;
import androidx.compose.animation.d0;
import androidx.compose.ui.node.B;
import androidx.lifecycle.X;
import androidx.room.n;
import androidx.room.w;
import androidx.work.C1425f;
import androidx.work.C1437k;
import androidx.work.D;
import androidx.work.EnumC1420a;
import androidx.work.impl.WorkDatabase_Impl;
import androidx.work.impl.model.q;
import androidx.work.impl.model.s;
import androidx.work.impl.r;
import androidx.work.impl.utils.g;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3390s2;
import com.google.android.gms.internal.mlkit_vision_camera.Y1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.K;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTCustomConfigurator;
import com.onetrust.otpublishers.headless.Public.DataModel.OTProfileSyncParams;
import com.onetrust.otpublishers.headless.Public.DataModel.OTProxyType;
import com.onetrust.otpublishers.headless.Public.DataModel.OTSdkParams;
import com.onetrust.otpublishers.headless.Public.OTCallback;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.Response.OTResponse;
import com.onetrust.otpublishers.headless.Public.Response.OTResponseType;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.quizletandroid.R;
import com.quizlet.remote.model.notes.e;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.l;
import okhttp3.A;
import okhttp3.C;
import okhttp3.H;
import okhttp3.internal.http.f;
import okhttp3.t;
import okhttp3.u;
import okhttp3.z;
import org.json.JSONException;
import org.json.JSONObject;
import retrofit2.C5177b;

/* loaded from: classes2.dex */
public final class d {
    public final Context a;
    public String b;
    public final com.onetrust.otpublishers.headless.Internal.Preferences.d c;
    public final com.onetrust.otpublishers.headless.Internal.a d = new com.onetrust.otpublishers.headless.Internal.a();

    public d(@NonNull Context context) {
        this.a = context;
        this.c = new com.onetrust.otpublishers.headless.Internal.Preferences.d(context);
    }

    public static void d(String str, String str2, JSONObject jSONObject, boolean z, boolean z2) throws JSONException {
        String str3;
        if (jSONObject.has("consentString")) {
            jSONObject.remove("consentString");
        }
        if (z) {
            JSONObject jSONObject2 = new JSONObject();
            jSONObject2.put(DBUserFields.Names.USER_UPGRADE_TYPE, "tcfeu");
            jSONObject2.put("content", str);
            jSONObject.put("consentString", jSONObject2);
            str3 = "Consent logging for IAB template, setting tc string = " + str;
        } else if (z2) {
            JSONObject jSONObject3 = new JSONObject();
            jSONObject3.put(DBUserFields.Names.USER_UPGRADE_TYPE, "gpp");
            jSONObject3.put("content", str2);
            jSONObject.put("consentString", jSONObject3);
            str3 = "Consent logging for Gpp enabled template, setting consent string = " + str2;
        } else {
            str3 = "Consent logging for non-IAB template with Gpp disabled, not setting consent string";
        }
        OTLogger.c("NetworkRequestHandler", 4, str3);
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x0077  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String a() throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 289
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Network.d.a():java.lang.String");
    }

    /* JADX WARN: Removed duplicated region for block: B:110:0x02df A[Catch: JSONException -> 0x0118, TryCatch #7 {JSONException -> 0x0118, blocks: (B:33:0x00ef, B:35:0x010d, B:41:0x0123, B:43:0x0138, B:44:0x013e, B:47:0x0145, B:49:0x0155, B:51:0x0169, B:54:0x0172, B:56:0x019d, B:60:0x01ae, B:64:0x01bc, B:66:0x01df, B:68:0x01fe, B:72:0x020f, B:74:0x0216, B:75:0x022e, B:76:0x0234, B:80:0x0258, B:82:0x0263, B:89:0x027b, B:91:0x0286, B:96:0x029b, B:100:0x02a6, B:108:0x02d9, B:110:0x02df, B:112:0x02e9, B:118:0x0314, B:125:0x0342, B:124:0x033d, B:123:0x0327, B:126:0x034b, B:128:0x0365, B:132:0x0376, B:136:0x0384, B:107:0x02d3, B:106:0x02bd, B:120:0x0320, B:103:0x02b4), top: B:196:0x00ef, inners: #6, #10 }] */
    /* JADX WARN: Removed duplicated region for block: B:128:0x0365 A[Catch: JSONException -> 0x0118, TryCatch #7 {JSONException -> 0x0118, blocks: (B:33:0x00ef, B:35:0x010d, B:41:0x0123, B:43:0x0138, B:44:0x013e, B:47:0x0145, B:49:0x0155, B:51:0x0169, B:54:0x0172, B:56:0x019d, B:60:0x01ae, B:64:0x01bc, B:66:0x01df, B:68:0x01fe, B:72:0x020f, B:74:0x0216, B:75:0x022e, B:76:0x0234, B:80:0x0258, B:82:0x0263, B:89:0x027b, B:91:0x0286, B:96:0x029b, B:100:0x02a6, B:108:0x02d9, B:110:0x02df, B:112:0x02e9, B:118:0x0314, B:125:0x0342, B:124:0x033d, B:123:0x0327, B:126:0x034b, B:128:0x0365, B:132:0x0376, B:136:0x0384, B:107:0x02d3, B:106:0x02bd, B:120:0x0320, B:103:0x02b4), top: B:196:0x00ef, inners: #6, #10 }] */
    /* JADX WARN: Removed duplicated region for block: B:129:0x0372  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x0375  */
    /* JADX WARN: Removed duplicated region for block: B:134:0x0382  */
    /* JADX WARN: Removed duplicated region for block: B:135:0x0383  */
    /* JADX WARN: Removed duplicated region for block: B:139:0x038f A[Catch: JSONException -> 0x0393, TRY_ENTER, TryCatch #3 {JSONException -> 0x0393, blocks: (B:139:0x038f, B:142:0x0398), top: B:188:0x038d }] */
    /* JADX WARN: Removed duplicated region for block: B:142:0x0398 A[Catch: JSONException -> 0x0393, TRY_LEAVE, TryCatch #3 {JSONException -> 0x0393, blocks: (B:139:0x038f, B:142:0x0398), top: B:188:0x038d }] */
    /* JADX WARN: Removed duplicated region for block: B:151:0x03be  */
    /* JADX WARN: Removed duplicated region for block: B:15:0x008a  */
    /* JADX WARN: Removed duplicated region for block: B:172:0x0403  */
    /* JADX WARN: Removed duplicated region for block: B:198:0x03f8 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(int r29, java.lang.String r30, java.lang.String r31) {
        /*
            Method dump skipped, instructions count: 1066
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Network.d.b(int, java.lang.String, java.lang.String):void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v23, types: [androidx.camera.camera2.internal.c0] */
    public final void c(OTCallback oTCallback, OTPublishersHeadlessSDK oTPublishersHeadlessSDK, final String str, final String str2, final String str3, String str4, String str5) {
        String strT;
        String str6;
        String str7;
        Context context = this.a;
        final OTSdkParams oTSdkParamsA = com.onetrust.otpublishers.headless.Internal.a.a(context);
        if (com.onetrust.otpublishers.headless.Internal.a.j(str5)) {
            StringBuilder sb = new StringBuilder("https://mobile-data.");
            String str8 = str4 == null ? "" : str4;
            str7 = "onetrust.io";
            if (!com.onetrust.otpublishers.headless.Internal.a.j(str8)) {
                String strTrim = str8.trim();
                if (!com.onetrust.otpublishers.headless.Internal.a.j(strTrim)) {
                    str7 = "qa".equals(strTrim) ? "1trust.app" : "onetrust.io";
                    if ("dev".equals(strTrim)) {
                        str7 = "onetrust.dev";
                    }
                }
            }
            strT = android.support.v4.media.session.a.t(sb, str7, "/bannersdk/v2/applicationdata");
        } else {
            strT = str5;
        }
        this.b = strT;
        z zVar = new z();
        String string = context.getString(R.string.ot_sdk_version_name);
        String oTSdkAPIVersion = oTSdkParamsA.getOTSdkAPIVersion();
        if (com.onetrust.otpublishers.headless.Internal.a.j(oTSdkAPIVersion) || string.equals(oTSdkAPIVersion)) {
            K.c("SDK api version not overridden, using SDK version = ", 4, string, "NetworkRequestHandler");
            str6 = string;
        } else {
            OTLogger.c("OneTrust", 5, "API version has been overridden. This feature is for testing only. Do not go live with an overridden API version.");
            str6 = oTSdkAPIVersion;
        }
        final String str9 = str6;
        zVar.a(new u() { // from class: com.onetrust.otpublishers.headless.Internal.Network.c
            @Override // okhttp3.u
            public final H intercept(t tVar) {
                String strConcat;
                d dVar = this.a;
                dVar.getClass();
                f fVar = (f) tVar;
                C c = fVar.e;
                e eVarB = c.b();
                eVarB.l("location", str);
                eVarB.l("application", str2);
                eVarB.l("lang", str3);
                eVarB.l("sdkVersion", str9);
                com.onetrust.otpublishers.headless.Internal.Preferences.d dVar2 = dVar.c;
                String string2 = dVar2.b().contains("OT_SDK_API_FETCH_TIMESTAMP") ? dVar2.b().getString("OT_SDK_API_FETCH_TIMESTAMP", null) : null;
                OTLogger.c("NetworkRequestHandler", 3, "Last launch timestamp : " + string2);
                if (!com.onetrust.otpublishers.headless.Internal.a.j(string2)) {
                    eVarB.l("x-onetrust-lastlaunch", string2);
                    OTLogger.c("NetworkRequestHandler", 3, "Added Last launch timestamp to header");
                }
                OTSdkParams oTSdkParams = oTSdkParamsA;
                if (!com.onetrust.otpublishers.headless.Internal.a.j(oTSdkParams.getOTRegionCode())) {
                    eVarB.l("OT-Region-Code", oTSdkParams.getOTRegionCode());
                }
                if (!com.onetrust.otpublishers.headless.Internal.a.j(oTSdkParams.getOTCountryCode())) {
                    eVarB.l("OT-Country-Code", oTSdkParams.getOTCountryCode());
                }
                OTProfileSyncParams otProfileSyncParams = oTSdkParams.getOtProfileSyncParams();
                if (otProfileSyncParams == null || com.onetrust.otpublishers.headless.Internal.a.j(otProfileSyncParams.getSyncProfile()) || !Boolean.parseBoolean(otProfileSyncParams.getSyncProfile())) {
                    OTLogger.c("NetworkRequestHandler", 4, "OT Profile Sync params not set, sending syncProfile false.");
                    eVarB.l("fetchType", "APP_DATA_ONLY");
                } else {
                    eVarB.l("fetchType", "APP_DATA_AND_SYNC_PROFILE");
                    if (!com.onetrust.otpublishers.headless.Internal.a.j(otProfileSyncParams.getIdentifier())) {
                        eVarB.l("identifier", otProfileSyncParams.getIdentifier());
                    }
                    if (!com.onetrust.otpublishers.headless.Internal.a.j(otProfileSyncParams.getSyncProfileAuth())) {
                        eVarB.l("syncProfileAuth", otProfileSyncParams.getSyncProfileAuth());
                    }
                    if (!com.onetrust.otpublishers.headless.Internal.a.j(otProfileSyncParams.getTenantId())) {
                        eVarB.l("tenantId", otProfileSyncParams.getTenantId());
                    }
                    if (!com.onetrust.otpublishers.headless.Internal.a.j(otProfileSyncParams.getSyncGroupId())) {
                        eVarB.l("syncGroupId", otProfileSyncParams.getSyncGroupId());
                    }
                    String string3 = dVar2.b().getString("OT_ProfileSyncETag", null);
                    if (com.onetrust.otpublishers.headless.Internal.a.j(string3)) {
                        strConcat = "Empty ETag.";
                    } else {
                        eVarB.l("profileSyncETag", string3);
                        strConcat = "ETag set to Header = ".concat(string3);
                    }
                    OTLogger.c("NetworkRequestHandler", 3, strConcat);
                }
                eVarB.n(c.b, c.d);
                return fVar.b(eVarB.i());
            }
        });
        com.quizlet.data.repository.explanations.textbook.a aVar = new com.quizlet.data.repository.explanations.textbook.a(8);
        aVar.c("https://mobile-data.onetrust.io/");
        aVar.b(new C5177b(2));
        aVar.a = new A(zVar);
        a aVar2 = (a) aVar.e().b(a.class);
        StringBuilder sbH = AbstractC0147y.h("Requesting OTT data parameters : ", str, ", ", str2, ", ");
        sbH.append(str3);
        sbH.append(",");
        sbH.append(oTSdkParamsA.getOTCountryCode());
        sbH.append(",");
        sbH.append(oTSdkParamsA.getOTRegionCode());
        sbH.append(", ");
        sbH.append(str9);
        sbH.append(", Profile : ");
        sbH.append(oTSdkParamsA.getOtProfileSyncParams() == null ? null : oTSdkParamsA.getOtProfileSyncParams().toString());
        OTLogger.c("NetworkRequestHandler", 3, sbH.toString());
        try {
            androidx.work.impl.model.c cVar = new androidx.work.impl.model.c(this, false, oTCallback, 14);
            String proxyDomainURLString = OTCustomConfigurator.getProxyDomainURLString(new OTProxyType.SDKDataDownload(new URL(this.b)));
            if (proxyDomainURLString.isEmpty()) {
                proxyDomainURLString = this.b;
            } else {
                cVar = new c0(this, oTCallback, aVar2, str9, cVar, oTPublishersHeadlessSDK);
            }
            OTLogger.c("NetworkRequestHandler", 4, "Requesting OTT data from : " + proxyDomainURLString);
            OTLogger.c("NetworkRequestHandler", 4, " OTT data Download : Download OTT data started");
            aVar2.b(proxyDomainURLString).j(new com.quizlet.data.repository.progress.b(this, str9, cVar, oTPublishersHeadlessSDK));
        } catch (MalformedURLException e) {
            OTLogger.c("NetworkRequestHandler", 6, "Error while checking for proxy during fetch of SDK data: " + e.getMessage());
            OTResponse oTResponse = new OTResponse(OTResponseType.OT_ERROR, 7, context.getResources().getString(R.string.err_ott_callback_failure), "");
            if (oTCallback != null) {
                oTCallback.onFailure(oTResponse);
            }
        }
    }

    public final void e(String str, String str2, boolean z, T t) {
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        Intrinsics.checkNotNullParameter("ott_consent_log_base_url", "key");
        linkedHashMap.put("ott_consent_log_base_url", "https://cookies2-ds.dev.otdev.org/request/v1/");
        Intrinsics.checkNotNullParameter("ott_consent_log_end_point", "key");
        linkedHashMap.put("ott_consent_log_end_point", str);
        Intrinsics.checkNotNullParameter("ott_payload_id", "key");
        linkedHashMap.put("ott_payload_id", str2);
        Intrinsics.checkNotNullParameter("ott_consent_isProxy", "key");
        linkedHashMap.put("ott_consent_isProxy", Boolean.valueOf(z));
        C1437k c1437k = new C1437k(linkedHashMap);
        AbstractC3390s2.d(c1437k);
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        androidx.work.A networkType = androidx.work.A.b;
        Intrinsics.checkNotNullParameter(networkType, "networkType");
        C1425f c1425f = new C1425f(new g(null), networkType, false, false, false, false, -1L, -1L, CollectionsKt.A0(linkedHashSet));
        Intrinsics.checkNotNullParameter(ConsentUploadWorker.class, "workerClass");
        androidx.work.C c = (androidx.work.C) ((androidx.work.C) new androidx.work.C(ConsentUploadWorker.class).k(c1437k)).j(c1425f);
        EnumC1420a backoffPolicy = EnumC1420a.a;
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        Intrinsics.checkNotNullParameter(backoffPolicy, "backoffPolicy");
        Intrinsics.checkNotNullParameter(timeUnit, "timeUnit");
        c.a = true;
        q qVar = (q) c.c;
        qVar.l = backoffPolicy;
        long millis = timeUnit.toMillis(10000L);
        String str3 = q.y;
        if (millis > 18000000) {
            androidx.work.z.c().f(str3, "Backoff delay duration exceeds maximum value");
        }
        if (millis < 10000) {
            androidx.work.z.c().f(str3, "Backoff delay duration less than minimum value");
        }
        qVar.m = l.d(millis, 10000L, 18000000L);
        D d = (D) c.a();
        Context context = this.a;
        Intrinsics.checkNotNullParameter(context, "context");
        r rVarH = r.h(context);
        Intrinsics.checkNotNullExpressionValue(rVarH, "getInstance(context)");
        rVarH.b(d);
        if (t != null) {
            androidx.work.impl.model.t tVarU = rVarH.c.u();
            List listSingletonList = Collections.singletonList(d.a.toString());
            tVarU.getClass();
            StringBuilder sbU = d0.u("SELECT id, state, output, run_attempt_count, generation, required_network_type, required_network_request, requires_charging, requires_device_idle, requires_battery_not_low, requires_storage_not_low, trigger_content_update_delay, trigger_max_content_delay, content_uri_triggers, initial_delay, interval_duration, flex_duration, backoff_policy, backoff_delay_duration, last_enqueue_time, period_count, next_schedule_time_override, stop_reason FROM workspec WHERE id IN (");
            int size = listSingletonList.size();
            Y1.d(sbU, size);
            sbU.append(")");
            androidx.room.u uVarA = androidx.room.u.a(size, sbU.toString());
            Iterator it2 = listSingletonList.iterator();
            int i = 1;
            while (it2.hasNext()) {
                uVarA.g(i, (String) it2.next());
                i++;
            }
            WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) tVarU.a;
            String[] tableNames = {"WorkTag", "WorkProgress", "workspec"};
            s computeFunction = new s(tVarU, uVarA, 0);
            n nVar = workDatabase_Impl.e;
            nVar.getClass();
            Intrinsics.checkNotNullParameter(tableNames, "tableNames");
            Intrinsics.checkNotNullParameter(computeFunction, "computeFunction");
            String[] tableNames2 = nVar.d(tableNames);
            for (String str4 : tableNames2) {
                LinkedHashMap linkedHashMap2 = nVar.d;
                Locale locale = Locale.US;
                if (!linkedHashMap2.containsKey(B.k(locale, "US", str4, locale, "this as java.lang.String).toLowerCase(locale)"))) {
                    throw new IllegalArgumentException("There is no table with name ".concat(str4).toString());
                }
            }
            com.quizlet.data.repository.searchexplanations.c cVar = nVar.j;
            cVar.getClass();
            Intrinsics.checkNotNullParameter(tableNames2, "tableNames");
            Intrinsics.checkNotNullParameter(computeFunction, "computeFunction");
            w wVar = new w((WorkDatabase_Impl) cVar.b, cVar, computeFunction, tableNames2);
            com.google.mlkit.common.internal.model.a aVar = new com.google.mlkit.common.internal.model.a(5);
            Object obj = new Object();
            X x = new X(0);
            x.m(wVar, new androidx.work.impl.utils.f(rVarH.d, obj, aVar, x));
            x.g(new androidx.camera.camera2.internal.D(t, 3));
        }
    }

    public final void f(JSONObject jSONObject) throws JSONException {
        String str;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        Context context = this.a;
        String string = new com.onetrust.otpublishers.headless.Internal.Preferences.e(context).a.b().getString("OT_CONSENT_INTEGRATION_DATA", "");
        try {
        } catch (JSONException e) {
            Z.p("error while returning consent integration data, err: ", e, "OneTrust", 6);
        }
        JSONObject jSONObject2 = !com.onetrust.otpublishers.headless.Internal.a.j(string) ? new JSONObject(string) : null;
        boolean z = false;
        if (!retrofit2.adapter.rxjava3.d.o(jSONObject2) ? jSONObject2.optBoolean("EnableJWTAuthForKnownUsers") : false) {
            SharedPreferences sharedPreferences = context.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
            if (Z.r(Boolean.FALSE, context.getSharedPreferences("com.onetrust.otpublishers.headless.preference".concat("OTT_DEFAULT_USER"), 0), "OT_ENABLE_MULTI_PROFILE")) {
                z = true;
                fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(context, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            } else {
                fVar = null;
            }
            if (z) {
                sharedPreferences = fVar;
            }
            String string2 = sharedPreferences.getString("OTT_PROFILE_SYNC_PROFILE_AUTH", null);
            if (!com.onetrust.otpublishers.headless.Internal.a.j(string2)) {
                OTLogger.c("NetworkRequestHandler", 4, "OT Profile Sync params set, enableJWTAuthForKnownUsers is true.Setting authorization header : " + string2);
                jSONObject.put("authorization", string2);
                return;
            }
            str = "EnableJWTAuthForKnownUsers is true, OT Profile Sync params not set. Not setting the authorization header.";
        } else {
            str = "EnableJWTAuthForKnownUsers is set to false.Not setting the authorization header.";
        }
        OTLogger.c("NetworkRequestHandler", 4, str);
    }

    /* JADX WARN: Can't wrap try/catch for region: R(51:0|2|(9:4|(1:6)|7|(1:9)(1:10)|(1:13)|14|(2:16|(4:18|(5:20|479|21|22|(3:25|(4:28|29|26|492)|507))(1:35)|36|(2:38|(3:477|40|(1:42)(4:43|(3:46|47|44)|508|50))(1:50))(0))(0))(1:51)|52|(5:54|74|483|75|76)(3:485|55|(6:57|(8:59|(1:61)(1:64)|65|(1:67)|68|69|498|70)(0)|74|483|75|76)(0)))(1:79)|80|(1:82)(1:83)|(1:85)(1:86)|87|(1:96)(3:(1:90)|91|(0)(1:94))|95|97|(1:99)(1:100)|(1:102)(1:103)|104|(1:112)(3:(1:107)|108|(0)(1:111))|113|(3:121|465|122)|126|(5:504|127|(1:129)(1:132)|(1:134)|135)|(34:471|137|138|139|150|(2:152|(4:154|487|155|(1:157))(1:161))(0)|158|163|(1:165)(1:166)|(1:168)|502|169|(1:171)(1:175)|176|(2:178|(16:180|(1:203)(12:183|469|184|185|463|186|187|475|188|(1:190)(1:193)|(1:195)|196)|204|(1:206)|207|(1:244)(9:210|490|211|(8:214|215|505|216|217|(3:473|219|511)(2:222|(4:224|(1:226)(1:227)|228|510)(1:512))|229|212)|509|235|(1:237)(1:238)|(1:240)|241)|245|(4:249|(1:251)|252|(3:255|(4:258|(3:514|260|517)(1:516)|515|256)|513))|261|(1:263)|264|(1:330)(19:269|(1:271)(3:273|(6:276|(1:520)(2:283|(8:522|285|(2:287|(1:289))(1:290)|291|(2:293|(1:295))|296|525|523)(2:521|297))|282|524|523|274)|518)|272|298|(4:300|(1:302)|303|(1:305))(2:306|(1:308))|309|(1:311)|312|(1:314)|315|(1:317)|318|(1:320)|321|(1:323)|324|(1:326)|(1:328)|329)|(1:365)(3:(2:334|(2:336|(1:338)(1:339))(1:340))(1:341)|(1:363)(4:347|(1:349)|350|(2:352|(1:354))(2:355|(2:357|(2:359|(1:361))(1:362))))|364)|(2:(0)(1:379)|(2:384|(1:400)(7:390|494|391|(1:393)(1:396)|(1:398)|399|400))(5:382|496|383|384|(1:400)(0)))(1:371)|372|(2:384|(0)(0))(0))(1:402))(0)|(1:410)(3:405|481|406)|411|(4:416|(1:418)(1:419)|(1:421)|422)(1:413)|423|467|424|(1:426)|427|430|(1:432)(1:433)|(1:435)|436|(1:438)|439|(1:441)|442|(4:448|(1:450)(1:451)|(1:453)|454)(1:447)|(1:458)|(1:527)(2:461|462))(1:148)|149|139|150|(0)(0)|158|163|(0)(0)|(0)|502|169|(0)(0)|176|(0)(0)|(1:410)(0)|411|(0)(5:414|416|(0)(0)|(0)|422)|423|467|424|(0)|427|430|(0)(0)|(0)|436|(0)|439|(0)|442|(5:444|448|(0)(0)|(0)|454)(0)|(1:458)|(1:527)(1:526)) */
    /* JADX WARN: Code restructure failed: missing block: B:173:0x036d, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:174:0x036e, code lost:
    
        com.google.android.gms.measurement.internal.Z.p("error while getting mobile data json, err: ", r0, r11, 6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:428:0x0a82, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:429:0x0a83, code lost:
    
        com.google.android.gms.measurement.internal.Z.p("Could not save or initialize CCPA params, err: ", r0, r11, 5);
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:100:0x0234  */
    /* JADX WARN: Removed duplicated region for block: B:102:0x0239  */
    /* JADX WARN: Removed duplicated region for block: B:103:0x023b  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x0242  */
    /* JADX WARN: Removed duplicated region for block: B:112:0x024e  */
    /* JADX WARN: Removed duplicated region for block: B:115:0x0253 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:129:0x0297 A[Catch: Exception -> 0x02a2, TryCatch #21 {Exception -> 0x02a2, blocks: (B:127:0x027a, B:129:0x0297, B:135:0x02af, B:137:0x02bb), top: B:504:0x027a }] */
    /* JADX WARN: Removed duplicated region for block: B:132:0x02a9  */
    /* JADX WARN: Removed duplicated region for block: B:134:0x02ae  */
    /* JADX WARN: Removed duplicated region for block: B:148:0x02e8  */
    /* JADX WARN: Removed duplicated region for block: B:152:0x02f6 A[Catch: Exception -> 0x02e0, TRY_LEAVE, TryCatch #13 {Exception -> 0x02e0, blocks: (B:150:0x02f0, B:152:0x02f6, B:149:0x02ea, B:143:0x02dc, B:137:0x02bb), top: B:471:0x02bb, inners: #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:161:0x0334  */
    /* JADX WARN: Removed duplicated region for block: B:165:0x034a  */
    /* JADX WARN: Removed duplicated region for block: B:166:0x0355  */
    /* JADX WARN: Removed duplicated region for block: B:168:0x035a  */
    /* JADX WARN: Removed duplicated region for block: B:171:0x0367 A[Catch: JSONException -> 0x036d, TRY_LEAVE, TryCatch #20 {JSONException -> 0x036d, blocks: (B:169:0x035b, B:171:0x0367), top: B:502:0x035b }] */
    /* JADX WARN: Removed duplicated region for block: B:175:0x0374  */
    /* JADX WARN: Removed duplicated region for block: B:178:0x039a  */
    /* JADX WARN: Removed duplicated region for block: B:206:0x0449  */
    /* JADX WARN: Removed duplicated region for block: B:244:0x0536  */
    /* JADX WARN: Removed duplicated region for block: B:247:0x0544  */
    /* JADX WARN: Removed duplicated region for block: B:251:0x0556  */
    /* JADX WARN: Removed duplicated region for block: B:255:0x0566  */
    /* JADX WARN: Removed duplicated region for block: B:263:0x05dd  */
    /* JADX WARN: Removed duplicated region for block: B:266:0x0617 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:330:0x07a1  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00c1  */
    /* JADX WARN: Removed duplicated region for block: B:365:0x08d9  */
    /* JADX WARN: Removed duplicated region for block: B:373:0x0905  */
    /* JADX WARN: Removed duplicated region for block: B:381:0x091e A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:384:0x0943  */
    /* JADX WARN: Removed duplicated region for block: B:388:0x0953 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:38:0x00cd  */
    /* JADX WARN: Removed duplicated region for block: B:400:0x09b8  */
    /* JADX WARN: Removed duplicated region for block: B:402:0x09bf  */
    /* JADX WARN: Removed duplicated region for block: B:404:0x09cd A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:410:0x09fb  */
    /* JADX WARN: Removed duplicated region for block: B:413:0x0a11  */
    /* JADX WARN: Removed duplicated region for block: B:414:0x0a14  */
    /* JADX WARN: Removed duplicated region for block: B:418:0x0a57  */
    /* JADX WARN: Removed duplicated region for block: B:419:0x0a62  */
    /* JADX WARN: Removed duplicated region for block: B:421:0x0a67  */
    /* JADX WARN: Removed duplicated region for block: B:426:0x0a73 A[Catch: JSONException -> 0x0a82, TRY_LEAVE, TryCatch #2 {JSONException -> 0x0a82, blocks: (B:424:0x0a6d, B:426:0x0a73), top: B:467:0x0a6d }] */
    /* JADX WARN: Removed duplicated region for block: B:432:0x0aa4  */
    /* JADX WARN: Removed duplicated region for block: B:433:0x0aaf  */
    /* JADX WARN: Removed duplicated region for block: B:435:0x0ab4  */
    /* JADX WARN: Removed duplicated region for block: B:438:0x0abf  */
    /* JADX WARN: Removed duplicated region for block: B:441:0x0b08  */
    /* JADX WARN: Removed duplicated region for block: B:444:0x0b13  */
    /* JADX WARN: Removed duplicated region for block: B:448:0x0b30  */
    /* JADX WARN: Removed duplicated region for block: B:450:0x0b4a  */
    /* JADX WARN: Removed duplicated region for block: B:451:0x0b57  */
    /* JADX WARN: Removed duplicated region for block: B:453:0x0b5a  */
    /* JADX WARN: Removed duplicated region for block: B:456:0x0b66 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:460:0x0b8b A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:471:0x02bb A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00fe  */
    /* JADX WARN: Removed duplicated region for block: B:526:? A[ADDED_TO_REGION, RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0139  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x01de  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x01e9  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x01ee  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x01f0  */
    /* JADX WARN: Removed duplicated region for block: B:89:0x01fc  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x0216  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x0229  */
    /* JADX WARN: Type inference failed for: r11v3 */
    /* JADX WARN: Type inference failed for: r11v4 */
    /* JADX WARN: Type inference failed for: r11v45, types: [boolean] */
    /* JADX WARN: Type inference failed for: r11v46 */
    /* JADX WARN: Type inference failed for: r11v49, types: [org.json.JSONObject] */
    /* JADX WARN: Type inference failed for: r11v50 */
    /* JADX WARN: Type inference failed for: r11v51 */
    /* JADX WARN: Type inference failed for: r11v52 */
    /* JADX WARN: Type inference failed for: r11v53, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r11v73 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void g(retrofit2.K r50, java.lang.String r51, com.onetrust.otpublishers.headless.Public.OTCallback r52, android.os.Handler r53, com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK r54, boolean r55) {
        /*
            Method dump skipped, instructions count: 3002
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.onetrust.otpublishers.headless.Internal.Network.d.g(retrofit2.K, java.lang.String, com.onetrust.otpublishers.headless.Public.OTCallback, android.os.Handler, com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK, boolean):void");
    }

    public final boolean h() {
        Context context = this.a;
        OTProfileSyncParams otProfileSyncParams = com.onetrust.otpublishers.headless.Internal.a.a(context).getOtProfileSyncParams();
        return (otProfileSyncParams == null || com.onetrust.otpublishers.headless.Internal.a.j(otProfileSyncParams.getSyncProfile()) || !Boolean.parseBoolean(otProfileSyncParams.getSyncProfile()) || com.onetrust.otpublishers.headless.Internal.a.j(otProfileSyncParams.getSyncProfileAuth()) || !new com.onetrust.otpublishers.headless.Internal.Preferences.d(context).c()) ? false : true;
    }
}
