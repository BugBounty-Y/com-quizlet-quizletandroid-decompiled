package com.braze.models.dust;

import com.braze.communication.dust.j;
import com.braze.support.BrazeLogger;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class c {
    public static final /* synthetic */ c a = new c();

    public static final String b(JSONObject jSONObject) {
        return assistantMode.refactored.a.j("Failed to parse json. Returning unknown.\n", jSONObject);
    }

    public final e a(JSONObject json) throws JSONException {
        Intrinsics.checkNotNullParameter(json, "json");
        String string = json.getString(DBUserFields.Names.USER_UPGRADE_TYPE);
        d dVar = d.a;
        if (Intrinsics.b(string, "ccr")) {
            return new a();
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new j(json, 4), 7, (Object) null);
        return new b();
    }
}
