package com.braze.push;

import com.braze.push.BrazeFirebaseMessagingService;
import com.braze.push.BrazeNotificationFactory;
import com.braze.push.BrazeNotificationStyleFactory;
import com.braze.push.NotificationTrampolineActivity;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class k implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ k(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return NotificationTrampolineActivity.AnonymousClass7.invokeSuspend$lambda$0();
            case 1:
                return BrazeFirebaseMessagingService.Companion.handleBrazeRemoteMessage$lambda$2();
            case 2:
                return BrazeFirebaseMessagingService.Companion.handleBrazeRemoteMessage$lambda$3();
            case 3:
                return BrazeFirebaseMessagingService.Companion.invokeFallbackFirebaseService$lambda$9();
            case 4:
                return BrazeNotificationActionUtils.handleNotificationActionClicked$lambda$3();
            case 5:
                return BrazeNotificationActionUtils.handleNotificationActionClicked$lambda$4();
            case 6:
                return BrazeNotificationActionUtils.handleNotificationActionClicked$lambda$5();
            case 7:
                return BrazeNotificationActionUtils.handleNotificationActionClicked$lambda$6();
            case 8:
                return BrazeNotificationActionUtils.addNotificationActions$lambda$0();
            case 9:
                return BrazeNotificationActionUtils.addNotificationActions$lambda$1();
            case 10:
                return BrazeNotificationActionUtils.addNotificationAction$lambda$7();
            case 11:
                return BrazeNotificationFactory.createNotification$lambda$0();
            case 12:
                return BrazeNotificationFactory.Companion.populateNotificationBuilder$lambda$1();
            case 13:
                return BrazeNotificationFactory.Companion.populateNotificationBuilder$lambda$2();
            case 14:
                return BrazeNotificationStyleFactory.Companion.setStyleIfSupported$lambda$0();
            case 15:
                return BrazeNotificationStyleFactory.Companion.getConversationalPushStyle$lambda$23();
            case 16:
                return BrazeNotificationStyleFactory.Companion.getInlineImageStyle$lambda$11();
            case 17:
                return BrazeNotificationStyleFactory.Companion.getInlineImageStyle$lambda$12();
            case 18:
                return BrazeNotificationStyleFactory.Companion.getInlineImageStyle$lambda$13();
            case 19:
                return BrazeNotificationStyleFactory.Companion.getInlineImageStyle$lambda$15();
            case 20:
                return BrazeNotificationStyleFactory.Companion.getStoryStyle$lambda$9();
            case 21:
                return BrazeNotificationStyleFactory.Companion.getStoryStyle$lambda$10();
            case EventType.WINDOW_STATE /* 22 */:
                return BrazeNotificationStyleFactory.Companion.populatePushStoryPage$lambda$25();
            case EventType.AUDIO /* 23 */:
                return BrazeNotificationStyleFactory.Companion.populatePushStoryPage$lambda$26();
            case EventType.VIDEO /* 24 */:
                return BrazeNotificationStyleFactory.Companion.getNotificationStyle$lambda$1();
            case EventType.SUBS /* 25 */:
                return BrazeNotificationStyleFactory.Companion.populatePushStoryPage$lambda$27();
            case EventType.CDN /* 26 */:
                return BrazeNotificationStyleFactory.Companion.getNotificationStyle$lambda$2();
            case 27:
                return BrazeNotificationStyleFactory.Companion.getNotificationStyle$lambda$3();
            case 28:
                return BrazeNotificationStyleFactory.Companion.getNotificationStyle$lambda$4();
            default:
                return BrazeNotificationStyleFactory.Companion.getNotificationStyle$lambda$5();
        }
    }
}
