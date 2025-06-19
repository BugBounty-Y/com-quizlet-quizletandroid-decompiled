package com.braze.configuration;

import android.content.Context;
import android.content.SharedPreferences;
import com.braze.AbstractC1484j;
import com.braze.W;
import com.braze.support.BrazeLogger;
import com.braze.support.StringUtils;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e {
    public final SharedPreferences a;

    public e(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.appboy.offline.storagemap", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
        this.a = sharedPreferences;
    }

    public static final String a(String str) {
        return AbstractC1484j.a("Stored user ID is longer than 997 bytes. Truncating. Original user ID: ", str);
    }

    public static final String c(String str) {
        return AbstractC1484j.a("Offline user storage provider was given user ID longer than 997. Rejecting. User ID: ", str);
    }

    public final void b(String userId) {
        Intrinsics.checkNotNullParameter(userId, "userId");
        if (userId.length() == 0) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new h(0), 6, (Object) null);
        } else {
            if (StringUtils.getByteSize(userId) > 997) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new W(userId, 16), 6, (Object) null);
                return;
            }
            SharedPreferences.Editor editorEdit = this.a.edit();
            editorEdit.putString("last_user", userId);
            editorEdit.apply();
        }
    }

    public final String a() {
        String string = this.a.getString("last_user", "");
        String str = string != null ? string : "";
        if (StringUtils.getByteSize(str) <= 997) {
            return str;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new W(str, 15), 6, (Object) null);
        String strTruncateToByteLength = StringUtils.truncateToByteLength(str, 997);
        b(strTruncateToByteLength);
        return strTruncateToByteLength;
    }

    public static final String b() {
        return "userId is empty in updateLastUserId. Rejecting.";
    }
}
