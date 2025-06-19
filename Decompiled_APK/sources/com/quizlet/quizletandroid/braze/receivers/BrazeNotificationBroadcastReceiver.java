package com.quizlet.quizletandroid.braze.receivers;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.support.v4.media.session.a;
import com.quizlet.quizletandroid.ui.activitycenter.managers.b;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class BrazeNotificationBroadcastReceiver extends BroadcastReceiver {
    @Override // android.content.BroadcastReceiver
    public final void onReceive(Context context, Intent intent) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(intent, "intent");
        if (Intrinsics.b(intent.getAction(), a.k(context.getPackageName(), "com.braze.push.intent.NOTIFICATION_OPENED"))) {
            SharedPreferences sharedPreferences = context.getSharedPreferences("SYNCED_ACTIVITY_CENTER_SHARED_PREF", 0);
            Intrinsics.d(sharedPreferences);
            new b(sharedPreferences);
            Bundle bundleExtra = intent.getBundleExtra("extra");
            String campaignId = bundleExtra != null ? bundleExtra.getString("campaignId") : null;
            if (campaignId != null) {
                Intrinsics.checkNotNullParameter(campaignId, "campaignId");
                sharedPreferences.edit().putLong("CAMPAIGN_ID_KEY_PREFIX_".concat(campaignId), System.currentTimeMillis()).apply();
            }
        }
    }
}
