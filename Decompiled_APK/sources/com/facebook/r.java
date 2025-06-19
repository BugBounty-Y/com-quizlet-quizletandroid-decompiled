package com.facebook;

import android.content.SharedPreferences;
import com.facebook.internal.J;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.LinkedHashMap;
import kotlin.C4937f;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final /* synthetic */ class r implements q {
    public final /* synthetic */ int a;

    public /* synthetic */ r(int i) {
        this.a = i;
    }

    @Override // com.facebook.q
    public final void a(w response) throws JSONException {
        y yVar = y.d;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(response, "response");
                break;
            case 1:
                Intrinsics.checkNotNullParameter(response, "response");
                Intrinsics.checkNotNullParameter(response, "response");
                FacebookRequestError facebookRequestError = response.c;
                boolean zBooleanValue = false;
                Object obj = null;
                linkedHashMap = null;
                linkedHashMap = null;
                linkedHashMap = null;
                linkedHashMap = null;
                linkedHashMap = null;
                linkedHashMap = null;
                linkedHashMap = null;
                linkedHashMap = null;
                LinkedHashMap linkedHashMap = null;
                if (facebookRequestError != null) {
                    com.google.mlkit.common.sdkinternal.model.a aVar = com.facebook.internal.A.c;
                    com.google.mlkit.common.sdkinternal.model.a.w(yVar, "com.facebook.appevents.cloudbridge.c", " \n\nGraph Response Error: \n================\nResponse Error: %s\nResponse Error Exception: %s\n\n ", facebookRequestError.toString(), String.valueOf(response.c.i));
                    if (!com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.cloudbridge.c.class)) {
                        try {
                            SharedPreferences sharedPreferences = o.a().getSharedPreferences("com.facebook.sdk.CloudBridgeSavedCredentials", 0);
                            if (sharedPreferences != null) {
                                String string = sharedPreferences.getString("dataset_id", null);
                                String string2 = sharedPreferences.getString("endpoint", null);
                                String string3 = sharedPreferences.getString("access_key", null);
                                if (string != null && !StringsKt.O(string) && string2 != null && !StringsKt.O(string2) && string3 != null && !StringsKt.O(string3)) {
                                    LinkedHashMap linkedHashMap2 = new LinkedHashMap();
                                    linkedHashMap2.put("endpoint", string2);
                                    linkedHashMap2.put("dataset_id", string);
                                    linkedHashMap2.put("access_key", string3);
                                    com.google.mlkit.common.sdkinternal.model.a.w(yVar, "com.facebook.appevents.cloudbridge.c".toString(), " \n\nLoading Cloudbridge settings from saved Prefs: \n================\n DATASETID: %s\n URL: %s \n ACCESSKEY: %s \n\n ", string, string2, string3);
                                    linkedHashMap = linkedHashMap2;
                                }
                            }
                        } catch (Throwable th) {
                            com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.cloudbridge.c.class, th);
                        }
                    }
                    if (linkedHashMap != null) {
                        URL url = new URL(String.valueOf(linkedHashMap.get("endpoint")));
                        com.facebook.appevents.cloudbridge.h.a(String.valueOf(linkedHashMap.get("dataset_id")), url.getProtocol() + "://" + url.getHost(), String.valueOf(linkedHashMap.get("access_key")));
                        com.facebook.appevents.cloudbridge.c.a = true;
                        break;
                    }
                } else {
                    com.google.mlkit.common.sdkinternal.model.a aVar2 = com.facebook.internal.A.c;
                    com.google.mlkit.common.sdkinternal.model.a.w(yVar, "com.facebook.appevents.cloudbridge.c", " \n\nGraph Response Received: \n================\n%s\n\n ", response);
                    JSONObject jSONObject = response.b;
                    if (jSONObject != null) {
                        try {
                            obj = jSONObject.get("data");
                        } catch (NullPointerException e) {
                            com.google.mlkit.common.sdkinternal.model.a aVar3 = com.facebook.internal.A.c;
                            Intrinsics.checkNotNullExpressionValue("com.facebook.appevents.cloudbridge.c", "TAG");
                            com.google.mlkit.common.sdkinternal.model.a.w(yVar, "com.facebook.appevents.cloudbridge.c", "CloudBridge Settings API response is not a valid json: \n%s ", C4937f.b(e));
                            return;
                        } catch (JSONException e2) {
                            com.google.mlkit.common.sdkinternal.model.a aVar4 = com.facebook.internal.A.c;
                            Intrinsics.checkNotNullExpressionValue("com.facebook.appevents.cloudbridge.c", "TAG");
                            com.google.mlkit.common.sdkinternal.model.a.w(yVar, "com.facebook.appevents.cloudbridge.c", "CloudBridge Settings API response is not a valid json: \n%s ", C4937f.b(e2));
                            return;
                        }
                    }
                    Intrinsics.e(obj, "null cannot be cast to non-null type org.json.JSONArray");
                    HashMap mapH = J.h(new JSONObject((String) CollectionsKt.firstOrNull(J.g((JSONArray) obj))));
                    String str = (String) mapH.get("endpoint");
                    String str2 = (String) mapH.get("dataset_id");
                    String str3 = (String) mapH.get("access_key");
                    if (str == null || str2 == null || str3 == null) {
                        Intrinsics.checkNotNullExpressionValue("com.facebook.appevents.cloudbridge.c", "TAG");
                        com.google.mlkit.common.sdkinternal.model.a.v(yVar, "com.facebook.appevents.cloudbridge.c", "CloudBridge Settings API response doesn't have valid data");
                        break;
                    } else {
                        try {
                            com.facebook.appevents.cloudbridge.h.a(str2, str, str3);
                            com.facebook.appevents.cloudbridge.c.d(mapH);
                            if (mapH.get("is_enabled") != null) {
                                Object obj2 = mapH.get("is_enabled");
                                Intrinsics.e(obj2, "null cannot be cast to non-null type kotlin.Boolean");
                                zBooleanValue = ((Boolean) obj2).booleanValue();
                            }
                            com.facebook.appevents.cloudbridge.c.a = zBooleanValue;
                            break;
                        } catch (MalformedURLException e3) {
                            com.google.mlkit.common.sdkinternal.model.a aVar5 = com.facebook.internal.A.c;
                            Intrinsics.checkNotNullExpressionValue("com.facebook.appevents.cloudbridge.c", "TAG");
                            com.google.mlkit.common.sdkinternal.model.a.w(yVar, "com.facebook.appevents.cloudbridge.c", "CloudBridge Settings API response doesn't have valid url\n %s ", C4937f.b(e3));
                            return;
                        }
                    }
                }
                break;
            default:
                Intrinsics.checkNotNullParameter(response, "it");
                com.google.mlkit.common.sdkinternal.model.a aVar6 = com.facebook.internal.A.c;
                com.google.mlkit.common.sdkinternal.model.a.v(yVar, com.facebook.appevents.codeless.k.a(), "App index sent to FB!");
                break;
        }
    }
}
