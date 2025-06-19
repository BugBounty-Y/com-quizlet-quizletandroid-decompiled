package com.braze.storage;

import android.content.Context;
import android.content.SharedPreferences;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class g0 {
    public final SharedPreferences a;

    public g0(Context context, String str, String str2) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = assistantMode.refactored.a.g(0, context, "com.appboy.storage.session_storage", str, str2);
    }

    public static final String b() {
        return "Could not create new mutable session for open session.";
    }

    public static final String d() {
        return "Failed to set end time to now for session json data";
    }

    public final void a(com.braze.models.n session) throws JSONException {
        Intrinsics.checkNotNullParameter(session, "session");
        String str = session.a.b;
        JSONObject jSONObjectForJsonPut = session.forJsonPut();
        SharedPreferences.Editor editorEdit = this.a.edit();
        a(jSONObjectForJsonPut);
        editorEdit.putString(str, jSONObjectForJsonPut.toString());
        if (!session.d) {
            editorEdit.putString("current_open_session", str);
        } else if (Intrinsics.b(this.a.getString("current_open_session", ""), str)) {
            editorEdit.remove("current_open_session");
        }
        editorEdit.apply();
    }

    public final com.braze.models.n c() {
        String str = "";
        if (!this.a.contains("current_open_session")) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new B(5), 7, (Object) null);
            return null;
        }
        try {
            String string = this.a.getString(this.a.getString("current_open_session", ""), "");
            if (string != null) {
                str = string;
            }
            return new com.braze.models.n(new JSONObject(str));
        } catch (JSONException e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new B(6), 4, (Object) null);
            return null;
        }
    }

    public static final String a() {
        return "No stored open session in storage.";
    }

    public final void a(String sessionId) {
        Intrinsics.checkNotNullParameter(sessionId, "sessionId");
        SharedPreferences.Editor editorEdit = this.a.edit();
        editorEdit.remove(sessionId);
        if (Intrinsics.b(sessionId, this.a.getString("current_open_session", null))) {
            editorEdit.remove("current_open_session");
        }
        editorEdit.apply();
    }

    public final void a(JSONObject jSONObject) throws JSONException {
        if (jSONObject.has("end_time")) {
            return;
        }
        try {
            jSONObject.put("end_time", DateTimeUtils.nowInSecondsPrecise());
        } catch (JSONException e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new B(7), 4, (Object) null);
        }
    }
}
