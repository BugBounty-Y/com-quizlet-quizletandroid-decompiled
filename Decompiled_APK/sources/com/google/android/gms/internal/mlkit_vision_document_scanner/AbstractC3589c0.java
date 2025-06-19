package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import java.util.Locale;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.c0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3589c0 {
    public static final /* synthetic */ int a = 0;

    public static void a(Context context, OTPublishersHeadlessSDK oTPublishersHeadlessSDK, JSONObject jSONObject) {
        JSONObject jSONObject2;
        JSONObject jSONObject3 = jSONObject.has("otData") ? jSONObject.getJSONObject("otData") : null;
        if (jSONObject.has("vendorListData")) {
            JSONObject jSONObject4 = jSONObject.getJSONObject("vendorListData");
            JSONObject jSONObject5 = jSONObject4.has("iabData") ? jSONObject4.getJSONObject("iabData") : null;
            jSONObject2 = jSONObject4.has("googleData") ? jSONObject4.getJSONObject("googleData") : null;
            jSONObject = jSONObject5;
        } else {
            jSONObject2 = null;
        }
        com.onetrust.otpublishers.headless.Internal.profile.c cVar = new com.onetrust.otpublishers.headless.Internal.profile.c(context);
        if (cVar.m() == null) {
            cVar.a.b().edit().putString("OT_ACTIVE_PROFILE_ID", cVar.o().toLowerCase(Locale.US)).apply();
        }
        if (jSONObject3 != null) {
            new com.onetrust.otpublishers.headless.Internal.Network.d(context).g(null, jSONObject3.toString(), null, null, oTPublishersHeadlessSDK, false);
        }
        if (jSONObject != null) {
            new com.onetrust.otpublishers.headless.Internal.Helper.c(context).g(context, jSONObject.toString());
        }
        if (jSONObject2 != null) {
            com.onetrust.otpublishers.headless.Internal.Helper.a.b(context, jSONObject2.toString());
        }
    }
}
