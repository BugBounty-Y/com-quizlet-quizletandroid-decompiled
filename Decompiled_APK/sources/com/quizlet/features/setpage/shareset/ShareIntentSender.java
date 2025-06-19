package com.quizlet.features.setpage.shareset;

import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import com.amazon.device.ads.DTBMetricsConfiguration;
import com.google.android.gms.internal.mlkit_vision_barcode.Q6;
import com.quizlet.db.data.models.persisted.fields.DBOfflineEntityFields;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.quizletandroid.u;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class ShareIntentSender extends BroadcastReceiver {
    public static final /* synthetic */ int d = 0;
    public volatile boolean a = false;
    public final Object b = new Object();
    public EventLogger c;

    public final void a(Context context, Intent intent) {
        if (this.a) {
            return;
        }
        synchronized (this.b) {
            try {
                if (!this.a) {
                    this.c = (EventLogger) ((u) ((d) Q6.b(context))).l0.get();
                    this.a = true;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // android.content.BroadcastReceiver
    public final void onReceive(Context context, Intent intent) {
        Bundle extras;
        a(context, intent);
        if (context == null || intent == null || (extras = intent.getExtras()) == null) {
            return;
        }
        String string = extras.getString(DTBMetricsConfiguration.APSMETRICS_URL, "");
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        long j = extras.getLong("study_set_id", 0L);
        String string2 = extras.getString("uuid", "");
        Intrinsics.checkNotNullExpressionValue(string2, "getString(...)");
        int i = extras.getInt(DBOfflineEntityFields.Names.MODEL_TYPE, 0);
        long j2 = extras.getLong("user_id", 0L);
        com.quizlet.utmhelper.a aVar = new com.quizlet.utmhelper.a(j2 <= 0 ? null : Long.valueOf(j2), extras.getString("campaign"), extras.getString("medium"), extras.getString("source"));
        ComponentName componentName = (ComponentName) extras.getParcelable("android.intent.extra.CHOSEN_COMPONENT");
        String packageName = componentName != null ? componentName.getPackageName() : null;
        EventLogger eventLogger = this.c;
        if (eventLogger == null) {
            Intrinsics.m("eventLogger");
            throw null;
        }
        Long lValueOf = j <= 0 ? null : Long.valueOf(j);
        if (string2.length() == 0) {
            string2 = null;
        }
        eventLogger.u(string, lValueOf, string2, ((long) i) > 0 ? Integer.valueOf(i) : null, aVar, packageName);
    }
}
