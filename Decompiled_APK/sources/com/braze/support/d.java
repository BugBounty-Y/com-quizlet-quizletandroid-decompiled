package com.braze.support;

import com.braze.AbstractC1475a;
import com.braze.AbstractC1476b;
import com.braze.enums.BrazeDateFormat;
import com.braze.managers.E;
import com.braze.support.BrazeLogger;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import kotlin.collections.B;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class d {
    public static final d a = new d();
    public static final List b = B.j("$add", "$remove", "$update", "$identifier_key", "$identifier_value", "$new_object");

    public static final String a(String str) {
        return AbstractC1475a.a("Nested Custom Attribute Key '", str, "' is invalid.");
    }

    public static final String b(String str) {
        return AbstractC1476b.a("Custom attribute key cannot be blocklisted attribute: ", str, '.');
    }

    public static final String c() {
        return "Custom attribute key cannot be null.";
    }

    public static final String d() {
        return "Custom attribute value cannot be null.";
    }

    public static final boolean a(String str, Set blocklistedAttributes) {
        Intrinsics.checkNotNullParameter(blocklistedAttributes, "blocklistedAttributes");
        if (str == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) a, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new v(16), 6, (Object) null);
            return false;
        }
        if (!blocklistedAttributes.contains(str)) {
            return true;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) a, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new w(str, 7), 6, (Object) null);
        return false;
    }

    public static final String b() {
        return "JSON Object nested too deep (limit 50). Returning null.";
    }

    public static final boolean c(String str) {
        if (str != null) {
            return true;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) a, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new v(15), 6, (Object) null);
        return false;
    }

    public static final String d(Object obj) {
        return "JSON Object size (" + ((JSONObject) obj).toString().length() + " bytes) exceeds 76800";
    }

    public static final String b(Object obj) {
        return androidx.compose.ui.node.B.e(obj, "Could not add unsupported custom attribute type with value: ");
    }

    public static final String c(Object obj) {
        return androidx.compose.ui.node.B.e(obj, "Error parsing date ");
    }

    public final JSONObject a(JSONObject jSONObject, int i) throws JSONException {
        if (i > 50) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new v(17), 7, (Object) null);
            return null;
        }
        JSONObject jSONObject2 = new JSONObject();
        Iterator<String> itKeys = jSONObject.keys();
        Intrinsics.checkNotNullExpressionValue(itKeys, "keys(...)");
        while (itKeys.hasNext()) {
            String next = itKeys.next();
            String strEnsureBrazeFieldLength = ValidationUtils.ensureBrazeFieldLength(next);
            d dVar = a;
            if ((StringsKt.O(strEnsureBrazeFieldLength) | StringsKt.G(strEnsureBrazeFieldLength, "$", false) | StringsKt.G(strEnsureBrazeFieldLength, ".", false)) & (!b.contains(strEnsureBrazeFieldLength))) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) dVar, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new w(next, 8), 6, (Object) null);
            }
            if (!StringsKt.O(strEnsureBrazeFieldLength)) {
                if (jSONObject.isNull(next)) {
                    jSONObject2.put(next, JSONObject.NULL);
                } else {
                    Object obj = jSONObject.get(next);
                    Intrinsics.checkNotNullExpressionValue(obj, "get(...)");
                    Object objA = dVar.a(obj, i);
                    if (objA == null) {
                        return null;
                    }
                    jSONObject2.put(strEnsureBrazeFieldLength, objA);
                }
            }
        }
        return jSONObject2;
    }

    public final JSONArray a(JSONArray jSONArray, int i) throws JSONException {
        if (i > 50) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new v(18), 7, (Object) null);
            return null;
        }
        JSONArray jSONArray2 = new JSONArray();
        int length = jSONArray.length();
        for (int i2 = 0; i2 < length; i2++) {
            Object obj = jSONArray.get(i2);
            Intrinsics.checkNotNullExpressionValue(obj, "get(...)");
            Object objA = a(obj, i);
            if (objA == null) {
                return null;
            }
            jSONArray2.put(objA);
        }
        return jSONArray2;
    }

    public static final String a() {
        return "JSON Object nested too deep (limit 50). Returning null.";
    }

    public final Object a(Object value, int i) {
        Intrinsics.checkNotNullParameter(value, "value");
        if ((value instanceof Boolean) || (value instanceof Integer) || (value instanceof Float) || (value instanceof Long) || (value instanceof Double)) {
            return value;
        }
        if (value instanceof String) {
            return ValidationUtils.ensureBrazeFieldLength((String) value);
        }
        if (value instanceof Date) {
            try {
                return DateTimeUtils.formatDate$default((Date) value, BrazeDateFormat.LONG, null, 2, null);
            } catch (Exception e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.requests.framework.o((Date) value, 8), 4, (Object) null);
                return null;
            }
        }
        if (value instanceof JSONObject) {
            if (i == 0 && ((JSONObject) value).toString().length() > 76800) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new com.braze.communication.dust.j((JSONObject) value, 12), 6, (Object) null);
                return null;
            }
            return a((JSONObject) value, i + 1);
        }
        if (value instanceof JSONArray) {
            if (i == 0 && ((JSONArray) value).toString().length() > 76800) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new x(0, (JSONArray) value), 6, (Object) null);
                return null;
            }
            return a((JSONArray) value, i + 1);
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new E(value, 2), 6, (Object) null);
        return null;
    }

    public static final String a(Object obj) {
        return "JSON Array size (" + ((JSONArray) obj).toString().length() + " bytes) exceeds 76800";
    }
}
