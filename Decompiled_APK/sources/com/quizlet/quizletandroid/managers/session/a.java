package com.quizlet.quizletandroid.managers.session;

import android.content.Context;
import android.content.SharedPreferences;
import com.quizlet.eventlogger.IAppSessionIdManager;
import com.quizlet.features.match.highscore.b;
import java.util.UUID;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class a implements IAppSessionIdManager {
    public final Context a;

    public a(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    @Override // com.quizlet.eventlogger.IAppSessionIdManager
    public final void a(UUID appSessionId) {
        Intrinsics.checkNotNullParameter(appSessionId, "appSessionId");
        Context context = this.a;
        SharedPreferences sharedPreferences = new com.quizlet.quizletandroid.ui.promo.engine.a(context).a;
        if (!sharedPreferences.getString("PREF_CURRENT_SESSION_ID", "").equals(appSessionId.toString())) {
            sharedPreferences.edit().putInt("PREF_ABS_SESSION_COUNT", sharedPreferences.getInt("PREF_ABS_SESSION_COUNT", 0) + 1).putString("PREF_CURRENT_SESSION_ID", appSessionId.toString()).apply();
        }
        b bVar = new b(context);
        Intrinsics.checkNotNullParameter(appSessionId, "appSessionId");
        SharedPreferences sharedPreferences2 = bVar.b;
        String string = sharedPreferences2.getString("PREF_CURRENT_SESSION_ID", "");
        if ((string != null ? string : "").equals(appSessionId.toString())) {
            return;
        }
        sharedPreferences2.edit().putString("PREF_CURRENT_SESSION_ID", appSessionId.toString()).apply();
    }
}
