package com.braze.managers;

import android.content.Context;
import android.content.SharedPreferences;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.braze.managers.u, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1507u implements e0 {
    public final kotlin.k a;
    public final SharedPreferences b;

    public C1507u(Context context, String apiKey) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(apiKey, "apiKey");
        this.a = kotlin.l.b(new androidx.navigation.compose.w(context, 1));
        SharedPreferences sharedPreferencesG = assistantMode.refactored.a.g(0, context, "com.braze.device_id", null, apiKey);
        Intrinsics.checkNotNullExpressionValue(sharedPreferencesG, "getSharedPreferences(...)");
        this.b = sharedPreferencesG;
    }

    public static final SharedPreferences a(Context context) {
        return context.getSharedPreferences("com.appboy.device", 0);
    }

    public final String a() {
        String string = this.b.getString("device_id", null);
        if (string == null) {
            Object value = this.a.getValue();
            Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
            string = ((SharedPreferences) value).getString("device_id", null);
            Object value2 = this.a.getValue();
            Intrinsics.checkNotNullExpressionValue(value2, "getValue(...)");
            ((SharedPreferences) value2).edit().clear().apply();
        }
        if ((this.b.contains("persistent_device_id") ? !Intrinsics.b(this.b.getString("persistent_device_id", null), String.valueOf(722989291)) : false) || string == null) {
            string = androidx.compose.ui.node.B.f("toString(...)");
        }
        this.b.edit().putString("persistent_device_id", String.valueOf(722989291)).putString("device_id", string).apply();
        return string;
    }
}
