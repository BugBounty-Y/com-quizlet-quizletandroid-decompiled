package com.facebook;

import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Parcelable;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class h {
    public static h e;
    public static volatile h g;
    public final androidx.localbroadcastmanager.content.b a;
    public final Object b;
    public Parcelable c;
    public static final com.quizlet.shared.usecase.studiableMetadata.a d = new com.quizlet.shared.usecase.studiableMetadata.a(7);
    public static final com.google.android.material.shape.e f = new com.google.android.material.shape.e(8);

    public h(androidx.localbroadcastmanager.content.b localBroadcastManager, z profileCache) {
        Intrinsics.checkNotNullParameter(localBroadcastManager, "localBroadcastManager");
        Intrinsics.checkNotNullParameter(profileCache, "profileCache");
        this.a = localBroadcastManager;
        this.b = profileCache;
    }

    public void a(Profile profile, boolean z) {
        Profile profile2 = (Profile) this.c;
        this.c = profile;
        if (z) {
            SharedPreferences sharedPreferences = ((z) this.b).a;
            if (profile != null) {
                Intrinsics.checkNotNullParameter(profile, "profile");
                JSONObject jSONObject = new JSONObject();
                try {
                    jSONObject.put("id", profile.a);
                    jSONObject.put("first_name", profile.b);
                    jSONObject.put("middle_name", profile.c);
                    jSONObject.put("last_name", profile.d);
                    jSONObject.put("name", profile.e);
                    Uri uri = profile.f;
                    if (uri != null) {
                        jSONObject.put("link_uri", uri.toString());
                    }
                    Uri uri2 = profile.g;
                    if (uri2 != null) {
                        jSONObject.put("picture_uri", uri2.toString());
                    }
                } catch (JSONException unused) {
                    jSONObject = null;
                }
                if (jSONObject != null) {
                    sharedPreferences.edit().putString("com.facebook.ProfileManager.CachedProfile", jSONObject.toString()).apply();
                }
            } else {
                sharedPreferences.edit().remove("com.facebook.ProfileManager.CachedProfile").apply();
            }
        }
        if (profile2 == null ? profile == null : profile2.equals(profile)) {
            return;
        }
        Intent intent = new Intent("com.facebook.sdk.ACTION_CURRENT_PROFILE_CHANGED");
        intent.putExtra("com.facebook.sdk.EXTRA_OLD_PROFILE", profile2);
        intent.putExtra("com.facebook.sdk.EXTRA_NEW_PROFILE", profile);
        this.a.c(intent);
    }

    public h(androidx.localbroadcastmanager.content.b localBroadcastManager, com.airbnb.lottie.network.d authenticationTokenCache) {
        Intrinsics.checkNotNullParameter(localBroadcastManager, "localBroadcastManager");
        Intrinsics.checkNotNullParameter(authenticationTokenCache, "authenticationTokenCache");
        this.a = localBroadcastManager;
        this.b = authenticationTokenCache;
    }
}
