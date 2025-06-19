package com.braze;

import com.braze.Braze;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class C implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ C(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Braze.requestContentCardsRefreshFromCache$lambda$82();
            case 1:
                return Braze.performPushDeliveryFlush$lambda$204();
            case 2:
                return Braze.requestContentCardsRefresh$lambda$81$lambda$80();
            case 3:
                return Braze.subscribeToNewInAppMessages$lambda$108();
            case 4:
                return Braze.applyPendingRuntimeConfiguration$lambda$195$lambda$192();
            case 5:
                return Braze.applyPendingRuntimeConfiguration$lambda$195$lambda$193();
            case 6:
                return Braze.verifyProperSdkSetup$lambda$215();
            case 7:
                return Braze.verifyProperSdkSetup$lambda$216();
            case 8:
                return Braze.getConfigurationProviderSafe$lambda$221();
            case 9:
                return Braze.handleInAppMessageTestPush$lambda$188();
            case 10:
                return Braze.logFeedDisplayed$lambda$72();
            case 11:
                return Braze.validateAndStorePushId$lambda$208();
            case 12:
                return Braze.logPushNotificationActionClicked$lambda$63();
            case 13:
                return Braze.logPushMaxCampaign$lambda$206();
            case 14:
                return Braze.requestImmediateDataFlush$lambda$105();
            case 15:
                return Braze.getCurrentUser$lambda$139();
            case 16:
                return Braze.logPushNotificationOpened$lambda$62$lambda$59();
            case 17:
                return Braze.logPushNotificationOpened$lambda$62$lambda$61();
            case 18:
                return Braze.requestImmediateDataFlush$lambda$107$lambda$106();
            case 19:
                return Braze.logPushStoryPageClicked$lambda$71$lambda$69();
            case 20:
                return Braze.closeSession$lambda$41();
            case 21:
                return Braze.Companion.getInstance$lambda$6$lambda$5();
            case EventType.WINDOW_STATE /* 22 */:
                return Braze.Companion.disableSdk$lambda$24();
            case EventType.AUDIO /* 23 */:
                return Braze.Companion.stopInstance$lambda$38();
            case EventType.VIDEO /* 24 */:
                return Braze.Companion.stopInstance$lambda$41$lambda$39();
            case EventType.SUBS /* 25 */:
                return Braze.Companion.stopInstance$lambda$41$lambda$40();
            case EventType.CDN /* 26 */:
                return Braze.Companion.stopInstance$lambda$42();
            case 27:
                return Braze.Companion._get_isDisabled_$lambda$2();
            case 28:
                return Braze.Companion._get_isDisabled_$lambda$3();
            default:
                return Braze.Companion._get_isDisabled_$lambda$4();
        }
    }
}
