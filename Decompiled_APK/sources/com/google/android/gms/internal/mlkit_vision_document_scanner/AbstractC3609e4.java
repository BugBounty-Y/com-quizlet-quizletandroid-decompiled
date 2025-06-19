package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.SharedPreferences;
import android.os.Bundle;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.OTUIDisplayReason.OTUIDisplayReason;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.e4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3609e4 {
    public static final /* synthetic */ int a = 0;

    public static void a(androidx.fragment.app.I i, com.onetrust.otpublishers.headless.Internal.Event.a aVar, OTConfiguration oTConfiguration, OTUIDisplayReason oTUIDisplayReason, OTPublishersHeadlessSDK oTPublishersHeadlessSDK) {
        boolean z;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar;
        boolean z2;
        com.onetrust.otpublishers.headless.Internal.Preferences.f fVar2;
        if (com.onetrust.otpublishers.headless.Internal.a.g(i, OTFragmentTags.OT_PREFERENCE_CENTER_FRAGMENT_TAG)) {
            return;
        }
        OTLogger.c("OneTrust", 4, "Showing Preference Center");
        OTLogger.c("OneTrust", 4, oTUIDisplayReason.logReason());
        androidx.compose.foundation.lazy.grid.m mVar = new androidx.compose.foundation.lazy.grid.m(5, 4);
        mVar.f = oTUIDisplayReason;
        SharedPreferences sharedPreferences = i.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (new com.onetrust.otpublishers.headless.Internal.profile.c(i).t()) {
            fVar = new com.onetrust.otpublishers.headless.Internal.Preferences.f(i, sharedPreferences, sharedPreferences.getString("OT_ACTIVE_PROFILE_ID", ""));
            z = true;
        } else {
            z = false;
            fVar = null;
        }
        StringBuilder sb = new StringBuilder("ui type ");
        sb.append((z ? fVar : sharedPreferences).getInt("OT_UI_MODE_TYPE", 102));
        OTLogger.c("OneTrust", 4, sb.toString());
        if (z) {
            sharedPreferences = fVar;
        }
        if (sharedPreferences.getInt("OT_UI_MODE_TYPE", 102) == 101) {
            com.onetrust.otpublishers.headless.UI.TVUI.fragments.g gVar = new com.onetrust.otpublishers.headless.UI.TVUI.fragments.g();
            Bundle bundle = new Bundle();
            bundle.putString(OTFragmentTags.FRAGMENT_TAG, OTFragmentTags.OT_TV_MAIN_FRAGMENT_TAG);
            gVar.setArguments(bundle);
            gVar.v = aVar;
            gVar.w = 1;
            gVar.A = oTConfiguration;
            com.google.mlkit.common.internal.model.a.l(gVar, i, OTFragmentTags.OT_TV_MAIN_FRAGMENT_TAG);
        } else {
            com.onetrust.otpublishers.headless.UI.fragment.l lVar = new com.onetrust.otpublishers.headless.UI.fragment.l();
            Bundle bundle2 = new Bundle();
            bundle2.putString(OTFragmentTags.FRAGMENT_TAG, OTFragmentTags.OT_PREFERENCE_CENTER_FRAGMENT_TAG);
            lVar.setArguments(bundle2);
            lVar.c1 = aVar;
            lVar.d1 = oTConfiguration;
            if (oTConfiguration != null && oTConfiguration.issSncOTUIWithBYOUIMethodsEnabled()) {
                lVar.W = oTPublishersHeadlessSDK;
            }
            com.google.mlkit.common.internal.model.a.l(lVar, i, OTFragmentTags.OT_PREFERENCE_CENTER_FRAGMENT_TAG);
        }
        if (aVar != null) {
            aVar.a(mVar);
        } else {
            OTLogger.c("OneTrust", 6, "Error on sending UI events, listener set was found to be null.This could be because the activity has been recreated. \n Please set listener to get UI event callbacks.");
        }
        SharedPreferences sharedPreferences2 = i.getSharedPreferences("com.onetrust.otpublishers.headless.preferenceOTT_DEFAULT_USER", 0);
        if (com.google.android.gms.measurement.internal.Z.r(Boolean.FALSE, new com.onetrust.otpublishers.headless.Internal.Preferences.d(i, "OTT_DEFAULT_USER").b(), "OT_ENABLE_MULTI_PROFILE")) {
            fVar2 = new com.onetrust.otpublishers.headless.Internal.Preferences.f(i, sharedPreferences2, sharedPreferences2.getString("OT_ACTIVE_PROFILE_ID", ""));
            z2 = true;
        } else {
            z2 = false;
            fVar2 = null;
        }
        if (z2) {
            sharedPreferences2 = fVar2;
        }
        if (sharedPreferences2.getInt("OneTrustBannerShownToUser", -1) < 1) {
            com.onetrust.otpublishers.headless.Internal.a.b(i, 1);
        }
    }
}
