package com.braze;

import com.braze.Braze;
import com.braze.BrazeActivityLifecycleCallbackListener;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class M implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ M(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Braze.Companion.enableMockNetworkRequestsAndDropEventsMode$lambda$21$lambda$19();
            case 1:
                return Braze.Companion.getApiEndpoint$lambda$12$lambda$11$lambda$10();
            case 2:
                return Braze.Companion.getConfiguredApiKey$lambda$7();
            case 3:
                return Braze.Companion.requestTriggersIfInAppMessageTestPush$lambda$37();
            case 4:
                return Braze.Companion.enableMockNetworkRequestsAndDropEventsMode$lambda$21$lambda$20();
            case 5:
                return Braze.Companion.enableMockNetworkRequestsAndDropEventsMode$lambda$22();
            case 6:
                return Braze.Companion.shouldAllowSingletonInitialization$lambda$34();
            case 7:
                return Braze.Companion.shouldAllowSingletonInitialization$lambda$35();
            case 8:
                return Braze.Companion.shouldAllowSingletonInitialization$lambda$36();
            case 9:
                return Braze.Companion.enableSdk$lambda$25();
            case 10:
                return Braze.Companion.enableSdk$lambda$26();
            case 11:
                return Braze.Companion.disableSdk$lambda$23();
            case 12:
                return BrazeActivityLifecycleCallbackListener.onActivityPaused$lambda$9();
            case 13:
                return BrazeActivityLifecycleCallbackListener.onActivityResumed$lambda$6();
            case 14:
                return BrazeActivityLifecycleCallbackListener.shouldHandleLifecycleMethodsInActivity$lambda$11();
            case 15:
                return BrazeActivityLifecycleCallbackListener.Companion._get_activity_$lambda$0();
            case 16:
                return BrazeUser.setPhoneNumber$lambda$33();
            case 17:
                return BrazeUser.addToSubscriptionGroup$lambda$27();
            case 18:
                return BrazeUser.setCountry$lambda$19();
            case 19:
                return BrazeUser.setLocationCustomAttribute$lambda$63();
            case 20:
                return BrazeUser.setLanguage$lambda$23();
            case 21:
                return BrazeUser.setFirstName$lambda$8();
            case EventType.WINDOW_STATE /* 22 */:
                return BrazeUser.addToCustomAttributeArray$lambda$51();
            case EventType.AUDIO /* 23 */:
                return BrazeUser.setLastName$lambda$10();
            case EventType.VIDEO /* 24 */:
                return BrazeUser.setHomeCity$lambda$21();
            case EventType.SUBS /* 25 */:
                return BrazeUser.setLineId$lambda$38();
            case EventType.CDN /* 26 */:
                return BrazeUser.addAlias$lambda$4();
            case 27:
                return BrazeUser.addAlias$lambda$5();
            case 28:
                return BrazeUser.removeFromSubscriptionGroup$lambda$30();
            default:
                return BrazeUser.setCustomAttribute$lambda$70();
        }
    }
}
