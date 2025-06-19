package com.braze.managers;

import android.content.Context;
import android.content.SharedPreferences;
import com.braze.configuration.BrazeConfigurationProvider;
import com.braze.support.BrazeLogger;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class l0 implements g0 {
    public final BrazeConfigurationProvider a;
    public final SharedPreferences b;

    public l0(Context context, BrazeConfigurationProvider configurationProvider) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(configurationProvider, "configurationProvider");
        this.a = configurationProvider;
        SharedPreferences sharedPreferences = context.getSharedPreferences("com.braze.push_registration", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "getSharedPreferences(...)");
        this.b = sharedPreferences;
    }

    public static final String a(int i, int i2) {
        return android.support.v4.media.session.a.j("Stored push registration ID version code ", i, " does not match live version code ", ". Not returning saved registration ID.", i2);
    }

    public final synchronized String b() {
        int versionCode;
        int i;
        try {
            if (this.a.isFirebaseCloudMessagingRegistrationEnabled() || this.a.isAdmMessagingRegistrationEnabled()) {
                if (this.b.contains("version_code") && (versionCode = this.a.getVersionCode()) != (i = this.b.getInt("version_code", Integer.MIN_VALUE))) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new J(i, versionCode, 0), 6, (Object) null);
                    return null;
                }
            }
            if (this.b.contains("device_identifier")) {
                if (!Intrinsics.b(String.valueOf(722989291), this.b.getString("device_identifier", ""))) {
                    BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new D(27), 6, (Object) null);
                    return null;
                }
            }
            return this.b.getString("registration_id", null);
        } catch (Throwable th) {
            throw th;
        }
    }

    public static final String a() {
        return "Device identifier differs from saved device identifier. Returning null token.";
    }

    public final synchronized void a(String str) {
        if (str != null) {
            this.b.edit().putString("registration_id", str).putInt("version_code", this.a.getVersionCode()).putString("device_identifier", String.valueOf(722989291)).apply();
        } else {
            throw new NullPointerException("Provided push token is null. Cannot set null push token.");
        }
    }
}
