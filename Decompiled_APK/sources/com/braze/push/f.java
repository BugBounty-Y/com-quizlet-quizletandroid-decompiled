package com.braze.push;

import android.app.NotificationChannel;
import androidx.core.app.NotificationManagerCompat;
import com.braze.models.push.BrazeNotificationPayload;
import com.braze.push.BrazeFirebaseMessagingService;
import com.braze.push.BrazeNotificationStyleFactory;
import com.braze.push.BrazeNotificationUtils;
import com.braze.push.BrazePushReceiver;
import com.google.firebase.messaging.RemoteMessage;
import java.util.Map;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class f implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ f(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeNotificationUtils.sendPushActionIntent$lambda$79((BrazeNotificationUtils.BrazeNotificationBroadcastType) this.b);
            case 1:
                return BrazeFirebaseMessagingService.Companion.handleBrazeRemoteMessage$lambda$0((RemoteMessage) this.b);
            case 2:
                return BrazeFirebaseMessagingService.Companion.handleBrazeRemoteMessage$lambda$4((Map) this.b);
            case 3:
                return BrazeNotificationActionUtils.addNotificationActions$lambda$2((BrazeNotificationPayload.ActionButton) this.b);
            case 4:
                return BrazeNotificationStyleFactory.Companion.getConversationalPushStyle$lambda$22((BrazeNotificationPayload.ConversationMessage) this.b);
            case 5:
                return BrazeNotificationUtils.wakeScreenIfAppropriate$lambda$26((NotificationChannel) this.b);
            default:
                return BrazePushReceiver.Companion.handlePushNotificationPayload$lambda$23((NotificationManagerCompat) this.b);
        }
    }
}
