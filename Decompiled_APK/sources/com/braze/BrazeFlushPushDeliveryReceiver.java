package com.braze;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import com.braze.support.BrazeLogger;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public class BrazeFlushPushDeliveryReceiver extends BroadcastReceiver {
    public static final b0 Companion = new b0();

    /* JADX INFO: Access modifiers changed from: private */
    public static final String onReceive$lambda$0(Intent intent) {
        return "BrazeFlushPushDeliveryReceiver received intent: " + intent.getAction();
    }

    @Override // android.content.BroadcastReceiver
    public void onReceive(Context context, Intent intent) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(intent, "intent");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new J(1, intent), 7, (Object) null);
        if (Intrinsics.b(intent.getAction(), "com.braze.FLUSH_PUSH_DELIVERY")) {
            BrazeInternal.INSTANCE.performPushDeliveryFlush(context);
        }
    }
}
