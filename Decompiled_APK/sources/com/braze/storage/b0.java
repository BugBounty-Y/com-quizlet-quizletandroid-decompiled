package com.braze.storage;

import android.content.Context;
import android.content.SharedPreferences;
import java.util.EnumSet;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b0 {
    public final SharedPreferences a;

    public b0(Context context, String userId, String apiKey) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(userId, "userId");
        Intrinsics.checkNotNullParameter(apiKey, "apiKey");
        SharedPreferences sharedPreferencesG = assistantMode.refactored.a.g(0, context, "com.braze.storage.sdk_metadata_cache", userId, apiKey);
        Intrinsics.checkNotNullExpressionValue(sharedPreferencesG, "getSharedPreferences(...)");
        this.a = sharedPreferencesG;
    }

    public final void a(EnumSet sdkMetadata) {
        Intrinsics.checkNotNullParameter(sdkMetadata, "sdkMetadata");
        this.a.edit().putStringSet("tags", com.braze.support.f.a(sdkMetadata)).apply();
    }

    public final EnumSet b(EnumSet newSdkMetadata) {
        Intrinsics.checkNotNullParameter(newSdkMetadata, "newSdkMetadata");
        if (Intrinsics.b(com.braze.support.f.a(newSdkMetadata), this.a.getStringSet("tags", M.a))) {
            return null;
        }
        return newSdkMetadata;
    }
}
