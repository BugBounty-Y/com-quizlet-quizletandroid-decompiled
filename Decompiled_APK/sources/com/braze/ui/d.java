package com.braze.ui;

import androidx.compose.runtime.C0776c;
import androidx.compose.ui.text.input.A;
import com.braze.ui.actions.UriAction;
import com.braze.ui.actions.brazeactions.BrazeActionParser;
import com.braze.ui.inappmessage.BrazeInAppMessageManager;
import com.braze.ui.inappmessage.listeners.DefaultInAppMessageWebViewClientListener;
import com.braze.ui.inappmessage.utils.BackgroundInAppMessagePreparer;
import com.braze.ui.inappmessage.views.InAppMessageBaseView;
import com.braze.ui.support.UriUtils;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class d implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;

    public /* synthetic */ d(String str, int i) {
        this.a = i;
        this.b = str;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return UserJavascriptInterfaceBase.setEmailNotificationSubscriptionType$lambda$12(this.b);
            case 1:
                return UserJavascriptInterfaceBase.setDateOfBirth$lambda$7(this.b);
            case 2:
                return UserJavascriptInterfaceBase.setCustomLocationAttribute$lambda$25(this.b);
            case 3:
                return UserJavascriptInterfaceBase.setCustomLocationAttribute$lambda$26(this.b);
            case 4:
                return UserJavascriptInterfaceBase.incrementCustomUserAttribute$lambda$23(this.b);
            case 5:
                return UserJavascriptInterfaceBase.setGender$lambda$3(this.b);
            case 6:
                return UserJavascriptInterfaceBase.setCustomUserAttributeArray$lambda$19(this.b);
            case 7:
                return UserJavascriptInterfaceBase.setPushNotificationSubscriptionType$lambda$14(this.b);
            case 8:
                return UserJavascriptInterfaceBase.setDateOfBirth$lambda$5(this.b);
            case 9:
                return UserJavascriptInterfaceBase.setDateOfBirth$lambda$6(this.b);
            case 10:
                return UriAction.getIntentArrayWithConfiguredBackStack$lambda$10(this.b);
            case 11:
                return UriAction.getIntentArrayWithConfiguredBackStack$lambda$12(this.b);
            case 12:
                return UriAction.getWebViewActivityIntent$lambda$7(this.b);
            case 13:
                return BrazeActionParser.getBrazeActionVersionAndJson$lambda$8(this.b);
            case 14:
                return BrazeActionParser.execute$lambda$2(this.b);
            case 15:
                return BrazeInAppMessageManager.createBrazeUserChangeEventSubscriber$lambda$57$lambda$55(this.b);
            case 16:
                return DefaultInAppMessageWebViewClientListener.onOtherUrlAction$lambda$9(this.b);
            case 17:
                return DefaultInAppMessageWebViewClientListener.onOtherUrlAction$lambda$10(this.b);
            case 18:
                return DefaultInAppMessageWebViewClientListener.onOtherUrlAction$lambda$11(this.b);
            case 19:
                return BackgroundInAppMessagePreparer.prepareInAppMessageWithBitmapDownload$lambda$12(this.b);
            case 20:
                return BackgroundInAppMessagePreparer.handleLocalImage$lambda$15(this.b);
            case 21:
                return BackgroundInAppMessagePreparer.handleLocalImage$lambda$16(this.b);
            case EventType.WINDOW_STATE /* 22 */:
                return BackgroundInAppMessagePreparer.prepareInAppMessageWithZippedAssetHtml$lambda$4(this.b);
            case EventType.AUDIO /* 23 */:
                return BackgroundInAppMessagePreparer.prepareInAppMessageWithZippedAssetHtml$lambda$7(this.b);
            case EventType.VIDEO /* 24 */:
                return InAppMessageBaseView.Companion.getAppropriateImageUrl$lambda$0(this.b);
            case EventType.SUBS /* 25 */:
                return UriUtils.isActivityRegisteredInManifest$lambda$3(this.b);
            case EventType.CDN /* 26 */:
                return C0776c.z(new A(6, 0L, this.b));
            default:
                return C0776c.z(this.b);
        }
    }
}
