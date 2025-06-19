package com.quizlet.features.setpage.shareset;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.os.Build;
import com.amazon.device.ads.DTBMetricsConfiguration;
import com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields;
import com.quizlet.utm.a;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class c {
    public static IntentSender a(Context context, String url, Long l, int i, a.C0023a utmInfo, String str) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(utmInfo, "utmInfo");
        Intent intent = new Intent(context, (Class<?>) ShareIntentSender.class);
        intent.putExtra(DTBMetricsConfiguration.APSMETRICS_URL, url);
        intent.putExtra("study_set_id", l);
        intent.putExtra(DBOfflineEntityFields.Names.MODEL_TYPE, i);
        intent.putExtra("user_id", utmInfo.getUserId());
        a.c params = utmInfo.getParams();
        intent.putExtra("campaign", params != null ? params.getCampaign() : null);
        a.c params2 = utmInfo.getParams();
        intent.putExtra("medium", params2 != null ? params2.getMedium() : null);
        a.c params3 = utmInfo.getParams();
        intent.putExtra("source", params3 != null ? params3.getSource() : null);
        intent.putExtra("uuid", str);
        IntentSender intentSender = PendingIntent.getBroadcast(context, 0, intent, Build.VERSION.SDK_INT >= 31 ? 167772160 : 134217728).getIntentSender();
        Intrinsics.checkNotNullExpressionValue(intentSender, "getIntentSender(...)");
        return intentSender;
    }
}
