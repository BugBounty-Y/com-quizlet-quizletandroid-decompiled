package com.braze.models.outgoing;

import com.braze.AbstractC1476b;
import com.braze.enums.BrazeDateFormat;
import com.braze.managers.C;
import com.braze.models.IPutIntoJson;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import com.braze.support.StringUtils;
import com.braze.support.ValidationUtils;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public final class BrazeProperties implements IPutIntoJson<JSONObject> {
    public static final d Companion = new d();
    private JSONObject propertiesJSONObject;

    public BrazeProperties() {
        this.propertiesJSONObject = new JSONObject();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String addProperty$lambda$0(String str) {
        return AbstractC1476b.a("Value type is not supported. Cannot add property ", str, '.');
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String addProperty$lambda$1() {
        return "Caught json exception trying to add property.";
    }

    private final JSONObject clean(JSONObject jSONObject, boolean z) throws JSONException {
        ArrayList arrayList = new ArrayList();
        Iterator<String> itKeys = jSONObject.keys();
        while (itKeys.hasNext()) {
            String next = itKeys.next();
            Intrinsics.checkNotNullExpressionValue(next, "next(...)");
            arrayList.add(next);
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            String str = (String) it2.next();
            if (!z || Companion.a(str)) {
                Object obj = jSONObject.get(str);
                if (obj instanceof Date) {
                    jSONObject.put(str, DateTimeUtils.formatDate$default((Date) obj, BrazeDateFormat.LONG, null, 2, null));
                }
                if (obj instanceof JSONArray) {
                    jSONObject.put(str, e.a((JSONArray) obj));
                }
                if (obj instanceof JSONObject) {
                    jSONObject.put(str, clean((JSONObject) obj, false));
                }
            } else {
                jSONObject.remove(str);
            }
        }
        return jSONObject;
    }

    public static /* synthetic */ JSONObject clean$default(BrazeProperties brazeProperties, JSONObject jSONObject, boolean z, int i, Object obj) {
        if ((i & 2) != 0) {
            z = true;
        }
        return brazeProperties.clean(jSONObject, z);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String clone$lambda$2() {
        return "Failed to clone BrazeProperties";
    }

    public final BrazeProperties addProperty(String key, Object obj) throws JSONException {
        Intrinsics.checkNotNullParameter(key, "key");
        if (Companion.a(key)) {
            try {
                if (obj instanceof Long) {
                    this.propertiesJSONObject.put(ValidationUtils.ensureBrazeFieldLength(key), ((Number) obj).longValue());
                    return this;
                }
                if (obj instanceof Integer) {
                    this.propertiesJSONObject.put(ValidationUtils.ensureBrazeFieldLength(key), ((Number) obj).intValue());
                    return this;
                }
                if (obj instanceof Double) {
                    this.propertiesJSONObject.put(ValidationUtils.ensureBrazeFieldLength(key), ((Number) obj).doubleValue());
                    return this;
                }
                if (obj instanceof Boolean) {
                    this.propertiesJSONObject.put(ValidationUtils.ensureBrazeFieldLength(key), ((Boolean) obj).booleanValue());
                    return this;
                }
                if (obj instanceof Date) {
                    this.propertiesJSONObject.put(ValidationUtils.ensureBrazeFieldLength(key), DateTimeUtils.formatDate$default((Date) obj, BrazeDateFormat.LONG, null, 2, null));
                    return this;
                }
                if (obj instanceof String) {
                    this.propertiesJSONObject.put(ValidationUtils.ensureBrazeFieldLength(key), ValidationUtils.ensureBrazeFieldLength((String) obj));
                    return this;
                }
                if (obj instanceof JSONArray) {
                    this.propertiesJSONObject.put(ValidationUtils.ensureBrazeFieldLength(key), e.a((JSONArray) obj));
                    return this;
                }
                if (obj instanceof JSONObject) {
                    this.propertiesJSONObject.put(ValidationUtils.ensureBrazeFieldLength(key), clean$default(this, (JSONObject) obj, false, 2, null));
                    return this;
                }
                if (obj instanceof Map) {
                    this.propertiesJSONObject.put(ValidationUtils.ensureBrazeFieldLength(key), clean$default(this, new JSONObject(e.a((Map) obj)), false, 2, null));
                    return this;
                }
                if (obj == null) {
                    this.propertiesJSONObject.put(ValidationUtils.ensureBrazeFieldLength(key), JSONObject.NULL);
                    return this;
                }
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new C(key, 16), 6, (Object) null);
                Unit unit = Unit.a;
                return this;
            } catch (JSONException e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.models.j(29), 4, (Object) null);
            }
        }
        return this;
    }

    public final BrazeProperties clone() {
        try {
            return new BrazeProperties(new JSONObject(forJsonPut().toString()));
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) e, false, (Function0) new a(0), 4, (Object) null);
            return null;
        }
    }

    public final long getByteSize() {
        String string = this.propertiesJSONObject.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return StringUtils.getByteSize(string);
    }

    public final int getSize() {
        return this.propertiesJSONObject.length();
    }

    public final boolean isInvalid() {
        return getByteSize() > 51200;
    }

    @Override // com.braze.models.IPutIntoJson
    public JSONObject forJsonPut() {
        return this.propertiesJSONObject;
    }

    public BrazeProperties(JSONObject jsonObject) {
        Intrinsics.checkNotNullParameter(jsonObject, "jsonObject");
        this.propertiesJSONObject = new JSONObject();
        this.propertiesJSONObject = clean$default(this, jsonObject, false, 2, null);
    }
}
