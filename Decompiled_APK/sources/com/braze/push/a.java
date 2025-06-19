package com.braze.push;

import com.braze.push.BrazeFirebaseMessagingService;
import com.braze.push.BrazeNotificationStyleFactory;
import com.braze.push.BrazePushReceiver;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;

    public /* synthetic */ a(String str, int i) {
        this.a = i;
        this.b = str;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeFirebaseMessagingService.Companion.invokeFallbackFirebaseService$lambda$10(this.b);
            case 1:
                return BrazeFirebaseMessagingService.Companion.invokeFallbackFirebaseService$lambda$11(this.b);
            case 2:
                return BrazeFirebaseMessagingService.Companion.handleBrazeRemoteMessage$lambda$1(this.b);
            case 3:
                return BrazeFirebaseMessagingService.Companion.invokeFallbackFirebaseService$lambda$6(this.b);
            case 4:
                return BrazeFirebaseMessagingService.Companion.invokeFallbackFirebaseService$lambda$7(this.b);
            case 5:
                return BrazeFirebaseMessagingService.Companion.invokeFallbackFirebaseService$lambda$8(this.b);
            case 6:
                return BrazeNotificationActionUtils.addNotificationAction$lambda$8(this.b);
            case 7:
                return BrazeNotificationActionUtils.addNotificationAction$lambda$9(this.b);
            case 8:
                return BrazeNotificationStyleFactory.Companion.getBigPictureNotificationStyle$lambda$18(this.b);
            case 9:
                return BrazeNotificationUtils.handlePushStoryPageClicked$lambda$71(this.b);
            case 10:
                return BrazeNotificationUtils.getValidNotificationChannel$lambda$76(this.b);
            case 11:
                return BrazeNotificationUtils.getValidNotificationChannel$lambda$77(this.b);
            case 12:
                return BrazeNotificationUtils.prefetchBitmapsIfNewlyReceivedStoryPush$lambda$30$lambda$29(this.b);
            case 13:
                return BrazeNotificationUtils.getOrCreateNotificationChannelId$lambda$67(this.b);
            case 14:
                return BrazeNotificationUtils.getOrCreateNotificationChannelId$lambda$68(this.b);
            case 15:
                return BrazePushReceiver.Companion.handlePushNotificationPayload$lambda$16$lambda$15(this.b);
            case 16:
                return BrazePushReceiver.Companion.handleAdmRegistrationIntent$lambda$8(this.b);
            default:
                return BrazePushReceiver.Companion.handleAdmRegistrationIntent$lambda$9(this.b);
        }
    }
}
