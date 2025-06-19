package com.onetrust.otpublishers.headless.UI.viewmodel;

import android.app.Application;
import android.content.SharedPreferences;
import androidx.lifecycle.w0;
import androidx.lifecycle.y0;
import com.onetrust.otpublishers.headless.Internal.Preferences.f;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a implements y0 {
    public final Application a;
    public final OTPublishersHeadlessSDK b;

    public a(Application application, OTPublishersHeadlessSDK oTPublishersHeadlessSDK) {
        Intrinsics.checkNotNullParameter(application, "application");
        this.a = application;
        this.b = oTPublishersHeadlessSDK;
    }

    @Override // androidx.lifecycle.y0
    public final w0 a(Class modelClass) {
        f fVar;
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Application application = this.a;
        boolean z = false;
        SharedPreferences sharedPreferences = application.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (new com.onetrust.otpublishers.headless.Internal.profile.c(application).t()) {
            fVar = new f(application, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            fVar = null;
        }
        if (z) {
            sharedPreferences = fVar;
        }
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "OTSharedPreference(\n    …      ).sharedPreferences");
        OTPublishersHeadlessSDK oTPublishersHeadlessSDK = this.b;
        if (oTPublishersHeadlessSDK == null) {
            oTPublishersHeadlessSDK = new OTPublishersHeadlessSDK(application);
        }
        return new b(application, oTPublishersHeadlessSDK, sharedPreferences);
    }
}
