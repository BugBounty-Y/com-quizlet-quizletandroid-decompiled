package com.braze.push;

import com.braze.push.BrazeNotificationStyleFactory;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class d implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ d(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeNotificationStyleFactory.Companion.getBigPictureNotificationStyle$lambda$19();
            case 1:
                return BrazeNotificationStyleFactory.Companion.getBigPictureNotificationStyle$lambda$20();
            case 2:
                return BrazeNotificationStyleFactory.Companion.getConversationalPushStyle$lambda$21();
            case 3:
                return BrazeNotificationUtils.wakeScreenIfAppropriate$lambda$25();
            case 4:
                return BrazeNotificationUtils.wakeScreenIfAppropriate$lambda$27();
            case 5:
                return BrazeNotificationUtils.sendNotificationOpenedBroadcast$lambda$74();
            case 6:
                return BrazeNotificationUtils.refreshFeatureFlagsIfAppropriate$lambda$12();
            case 7:
                return BrazeNotificationUtils.refreshFeatureFlagsIfAppropriate$lambda$13();
            case 8:
                return BrazeNotificationUtils.handlePushStoryPageClicked$lambda$72();
            case 9:
                return BrazeNotificationUtils.requestGeofenceRefreshIfAppropriate$lambda$10();
            case 10:
                return BrazeNotificationUtils.requestGeofenceRefreshIfAppropriate$lambda$11();
            case 11:
                return BrazeNotificationUtils.refreshBannersIfAppropriate$lambda$14();
            case 12:
                return BrazeNotificationUtils.refreshBannersIfAppropriate$lambda$15();
            case 13:
                return BrazeNotificationUtils.sendPushMessageReceivedBroadcast$lambda$9();
            case 14:
                return BrazeNotificationUtils.cancelNotification$lambda$65();
            case 15:
                return BrazeNotificationUtils.routeUserWithNotificationOpenedIntent$lambda$4();
            case 16:
                return BrazeNotificationUtils.getValidNotificationChannel$lambda$75();
            case 17:
                return BrazeNotificationUtils.handleNotificationDeleted$lambda$2();
            case 18:
                return BrazeNotificationUtils.getValidNotificationChannel$lambda$78();
            case 19:
                return BrazeNotificationUtils.setDeleteIntent$lambda$35();
            case 20:
                return BrazeNotificationUtils.setContentIfPresent$lambda$32();
            case 21:
                return BrazeNotificationUtils.setSmallIcon$lambda$36();
            case EventType.WINDOW_STATE /* 22 */:
                return BrazeNotificationUtils.handleNotificationDeleted$lambda$3();
            case EventType.AUDIO /* 23 */:
                return BrazeNotificationUtils.setSmallIcon$lambda$37();
            case EventType.VIDEO /* 24 */:
                return BrazeNotificationUtils.setSetShowWhen$lambda$38();
            case EventType.SUBS /* 25 */:
                return BrazeNotificationUtils.setSoundIfPresentAndSupported$lambda$46();
            case EventType.CDN /* 26 */:
                return BrazeNotificationUtils.setSoundIfPresentAndSupported$lambda$47();
            case 27:
                return BrazeNotificationUtils.setPriorityIfPresentAndSupported$lambda$50();
            case 28:
                return BrazeNotificationUtils.setCategoryIfPresentAndSupported$lambda$54();
            default:
                return BrazeNotificationUtils.setCategoryIfPresentAndSupported$lambda$55();
        }
    }
}
