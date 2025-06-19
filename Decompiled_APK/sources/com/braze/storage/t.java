package com.braze.storage;

import android.content.Context;
import android.content.SharedPreferences;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;

/* loaded from: classes.dex */
public final class t {
    public static final long b = TimeUnit.DAYS.toMillis(7);
    public final SharedPreferences a;

    public t(Context context, String str, String apiKey) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(apiKey, "apiKey");
        SharedPreferences sharedPreferencesG = assistantMode.refactored.a.g(0, context, "com.appboy.storage.event_data_validator", str, apiKey);
        Intrinsics.checkNotNullExpressionValue(sharedPreferencesG, "getSharedPreferences(...)");
        this.a = sharedPreferencesG;
        a();
    }

    public static final String b(com.braze.models.i iVar) {
        return "Event already seen in cache. Ignoring duplicate: " + iVar;
    }

    public final boolean a(com.braze.models.i event) throws JSONException {
        Intrinsics.checkNotNullParameter(event, "event");
        com.braze.models.outgoing.event.b bVar = (com.braze.models.outgoing.event.b) event;
        if (bVar.a != com.braze.enums.e.h) {
            return true;
        }
        a();
        Intrinsics.checkNotNullParameter(event, "event");
        int i = com.braze.models.outgoing.event.push.b.j;
        Intrinsics.checkNotNullParameter(event, "event");
        String string = bVar.b.getString("cid");
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        String eventKey = bVar.a + string;
        if (this.a.contains(eventKey)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.dispatch.n(event, 9), 7, (Object) null);
            return false;
        }
        long jNowInMilliseconds = DateTimeUtils.nowInMilliseconds() + b;
        Intrinsics.checkNotNullParameter(eventKey, "eventKey");
        this.a.edit().putLong(eventKey, jNowInMilliseconds).apply();
        return true;
    }

    public final void a() {
        long jNowInMilliseconds = DateTimeUtils.nowInMilliseconds();
        for (Map.Entry<String, ?> entry : this.a.getAll().entrySet()) {
            try {
                Object value = entry.getValue();
                Intrinsics.e(value, "null cannot be cast to non-null type kotlin.Long");
                if (jNowInMilliseconds >= ((Long) value).longValue()) {
                    String key = entry.getKey();
                    Intrinsics.checkNotNullExpressionValue(key, "<get-key>(...)");
                    this.a.edit().remove(key).apply();
                }
            } catch (Exception e) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new com.braze.requests.framework.o(entry, 7), 4, (Object) null);
                String key2 = entry.getKey();
                Intrinsics.checkNotNullExpressionValue(key2, "<get-key>(...)");
                this.a.edit().remove(key2).apply();
            }
        }
    }

    public static final String a(Map.Entry entry) {
        return "Failed to get expiration time. Deleting entry: " + entry;
    }
}
