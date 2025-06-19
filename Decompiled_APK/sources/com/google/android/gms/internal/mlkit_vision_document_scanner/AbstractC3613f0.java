package com.google.android.gms.internal.mlkit_vision_document_scanner;

import com.onetrust.otpublishers.headless.Public.uiutils.OTVendorUtils;
import java.util.ArrayList;
import java.util.Locale;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.f0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3613f0 {
    public static final /* synthetic */ int a = 0;

    public static final ArrayList a(JSONObject jSONObject, boolean z) throws JSONException {
        JSONArray jSONArray;
        com.onetrust.otpublishers.headless.UI.DataModels.j jVar;
        int i;
        int i2;
        ArrayList arrayList = new ArrayList();
        JSONArray jSONArrayNames = jSONObject.names();
        if (jSONArrayNames != null) {
            int length = jSONArrayNames.length();
            int i3 = 0;
            while (i3 < length) {
                JSONObject itemJson = jSONObject.getJSONObject(jSONArrayNames.get(i3).toString());
                com.onetrust.otpublishers.headless.UI.DataModels.k kVar = com.onetrust.otpublishers.headless.UI.DataModels.k.b;
                com.onetrust.otpublishers.headless.UI.DataModels.k kVar2 = com.onetrust.otpublishers.headless.UI.DataModels.k.a;
                com.onetrust.otpublishers.headless.UI.DataModels.k kVar3 = com.onetrust.otpublishers.headless.UI.DataModels.k.d;
                com.onetrust.otpublishers.headless.UI.DataModels.k kVar4 = com.onetrust.otpublishers.headless.UI.DataModels.k.c;
                if (z) {
                    Intrinsics.checkNotNullExpressionValue(itemJson, "itemJson");
                    String string = jSONArrayNames.get(i3).toString();
                    jSONArray = jSONArrayNames;
                    String strB = AbstractC3657k4.b(itemJson, "Name", "");
                    Intrinsics.checkNotNullParameter(itemJson, "<this>");
                    Intrinsics.checkNotNullParameter(OTVendorUtils.CONSENT_TYPE, "key");
                    try {
                        i2 = itemJson.getInt(OTVendorUtils.CONSENT_TYPE);
                    } catch (Exception unused) {
                        i2 = -1;
                    }
                    if (i2 != 0) {
                        kVar = i2 != 1 ? i2 != 2 ? kVar4 : kVar3 : kVar2;
                    }
                    jVar = new com.onetrust.otpublishers.headless.UI.DataModels.j(string, strB, kVar);
                } else {
                    jSONArray = jSONArrayNames;
                    Intrinsics.checkNotNullExpressionValue(itemJson, "itemJson");
                    String strB2 = AbstractC3657k4.b(itemJson, "id", "-1");
                    String strB3 = AbstractC3657k4.b(itemJson, "name", "");
                    Intrinsics.checkNotNullParameter(itemJson, "<this>");
                    Intrinsics.checkNotNullParameter(OTVendorUtils.CONSENT_TYPE, "key");
                    try {
                        i = itemJson.getInt(OTVendorUtils.CONSENT_TYPE);
                    } catch (Exception unused2) {
                        i = -1;
                    }
                    if (i != 0) {
                        kVar = i != 1 ? i != 2 ? kVar4 : kVar3 : kVar2;
                    }
                    jVar = new com.onetrust.otpublishers.headless.UI.DataModels.j(strB2, strB3, kVar);
                }
                arrayList.add(jVar);
                i3++;
                jSONArrayNames = jSONArray;
            }
        }
        return arrayList;
    }

    public static final JSONObject b(boolean z, String searchQuery, JSONObject jSONObject, JSONObject vendorObject) throws JSONException {
        JSONArray jSONArrayNames;
        Intrinsics.checkNotNullParameter(jSONObject, "<this>");
        Intrinsics.checkNotNullParameter(searchQuery, "searchQuery");
        Intrinsics.checkNotNullParameter(vendorObject, "vendorObject");
        JSONObject jSONObject2 = new JSONObject();
        if (searchQuery.length() == 0 || (jSONArrayNames = vendorObject.names()) == null) {
            return vendorObject;
        }
        String str = z ? "Name" : "name";
        int length = jSONArrayNames.length();
        for (int i = 0; i < length; i++) {
            String string = jSONArrayNames.getString(i);
            JSONObject jSONObject3 = vendorObject.getJSONObject(string);
            String string2 = jSONObject3.getString(str);
            Intrinsics.checkNotNullExpressionValue(string2, "vendor.getString(nameKey)");
            Locale locale = Locale.ENGLISH;
            if (StringsKt.G(androidx.compose.ui.node.B.k(locale, "ENGLISH", string2, locale, "this as java.lang.String).toLowerCase(locale)"), searchQuery, true)) {
                jSONObject2.put(string, jSONObject3);
            }
        }
        return jSONObject2;
    }
}
