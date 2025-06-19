package com.braze.push;

import com.braze.push.BrazePushReceiver;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class i implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ i(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeNotificationUtils.setVisibilityIfPresentAndSupported$lambda$56();
            case 1:
                return BrazeNotificationUtils.handleNotificationOpened$lambda$0();
            case 2:
                return BrazeNotificationUtils.setTickerIfPresent$lambda$33();
            case 3:
                return BrazeNotificationUtils.setSummaryTextIfPresentAndSupported$lambda$48();
            case 4:
                return BrazeNotificationUtils.setSummaryTextIfPresentAndSupported$lambda$49();
            case 5:
                return BrazeNotificationUtils.setAccentColorIfPresentAndSupported$lambda$51();
            case 6:
                return BrazeNotificationUtils.setAccentColorIfPresentAndSupported$lambda$53$lambda$52();
            case 7:
                return BrazeNotificationUtils.setContentIntentIfPresent$lambda$34();
            case 8:
                return BrazeNotificationUtils.setTitleIfPresent$lambda$31();
            case 9:
                return BrazeNotificationUtils.setLargeIconIfPresentAndSupported$lambda$39();
            case 10:
                return BrazeNotificationUtils.setLargeIconIfPresentAndSupported$lambda$40();
            case 11:
                return BrazeNotificationUtils.handleNotificationOpened$lambda$1();
            case 12:
                return BrazeNotificationUtils.setLargeIconIfPresentAndSupported$lambda$42();
            case 13:
                return BrazeNotificationUtils.setLargeIconIfPresentAndSupported$lambda$43();
            case 14:
                return BrazeNotificationUtils.setLargeIconIfPresentAndSupported$lambda$44();
            case 15:
                return BrazeNotificationUtils.setLargeIconIfPresentAndSupported$lambda$45();
            case 16:
                return BrazeNotificationUtils.getOrCreateNotificationChannelId$lambda$69();
            case 17:
                return BrazeNotificationUtils.handleCancelNotificationAction$lambda$63();
            case 18:
                return BrazeNotificationUtils.wakeScreenIfAppropriate$lambda$23();
            case 19:
                return BrazeNotificationUtils.wakeScreenIfAppropriate$lambda$24();
            case 20:
                return BrazePushReceiver.Companion.handlePushNotificationPayload$lambda$14();
            case 21:
                return BrazePushReceiver.Companion.handlePushNotificationPayload$lambda$17();
            case EventType.WINDOW_STATE /* 22 */:
                return BrazePushReceiver.Companion.handlePushNotificationPayload$lambda$18();
            case EventType.AUDIO /* 23 */:
                return BrazePushReceiver.Companion.handlePushNotificationPayload$lambda$19();
            case EventType.VIDEO /* 24 */:
                return BrazePushReceiver.Companion.handlePushNotificationPayload$lambda$20();
            case EventType.SUBS /* 25 */:
                return BrazePushReceiver.Companion.handleAdmRegistrationEventIfEnabled$lambda$5();
            case EventType.CDN /* 26 */:
                return BrazePushReceiver.Companion.handleAdmRegistrationEventIfEnabled$lambda$6();
            case 27:
                return BrazePushReceiver.Companion.handleAdmRegistrationIntent$lambda$10();
            case 28:
                return BrazePushReceiver.Companion.handlePush$performWork$lambda$2();
            default:
                return BrazePushReceiver.Companion.handlePushNotificationPayload$lambda$11();
        }
    }
}
