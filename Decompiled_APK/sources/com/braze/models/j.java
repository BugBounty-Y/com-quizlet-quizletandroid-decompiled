package com.braze.models;

import com.braze.models.cards.Card;
import com.braze.models.inappmessage.InAppMessageBase;
import com.braze.models.inappmessage.InAppMessageControl;
import com.braze.models.inappmessage.InAppMessageHtmlBase;
import com.braze.models.inappmessage.InAppMessageImmersiveBase;
import com.braze.models.inappmessage.InAppMessageSlideup;
import com.braze.models.inappmessage.MessageButton;
import com.braze.models.outgoing.BrazeProperties;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class j implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ j(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return a.b();
            case 1:
                return Card._set_isIndicatorHighlighted_$lambda$0();
            case 2:
                return Card._set_isDismissed_$lambda$1();
            case 3:
                return Card._set_isDismissed_$lambda$3();
            case 4:
                return Card.isValidCard$lambda$17();
            case 5:
                return InAppMessageBase.forJsonPut$lambda$9();
            case 6:
                return InAppMessageBase.logImpression$lambda$4();
            case 7:
                return InAppMessageBase.logImpression$lambda$5();
            case 8:
                return InAppMessageBase.logImpression$lambda$3();
            case 9:
                return InAppMessageBase.enableDarkTheme$lambda$6();
            case 10:
                return InAppMessageBase.handleLogClick$lambda$11();
            case 11:
                return InAppMessageBase.handleLogClick$lambda$12();
            case 12:
                return InAppMessageBase.handleLogClick$lambda$10();
            case 13:
                return InAppMessageControl.logImpression$lambda$0();
            case 14:
                return InAppMessageControl.logImpression$lambda$2();
            case 15:
                return InAppMessageControl.logImpression$lambda$3();
            case 16:
                return InAppMessageControl.logImpression$lambda$1();
            case 17:
                return InAppMessageHtmlBase.logButtonClick$lambda$1();
            case 18:
                return InAppMessageHtmlBase.logButtonClick$lambda$2();
            case 19:
                return InAppMessageHtmlBase.logButtonClick$lambda$3();
            case 20:
                return InAppMessageImmersiveBase.enableDarkTheme$lambda$5();
            case 21:
                return InAppMessageImmersiveBase.logButtonClick$lambda$2();
            case EventType.WINDOW_STATE /* 22 */:
                return InAppMessageImmersiveBase.logButtonClick$lambda$3();
            case EventType.AUDIO /* 23 */:
                return InAppMessageImmersiveBase.logButtonClick$lambda$1();
            case EventType.VIDEO /* 24 */:
                return InAppMessageSlideup.enableDarkTheme$lambda$0();
            case EventType.SUBS /* 25 */:
                return InAppMessageSlideup.forJsonPut$lambda$2();
            case EventType.CDN /* 26 */:
                return MessageButton.enableDarkTheme$lambda$2$lambda$1();
            case 27:
                return com.braze.models.inappmessage.b.a();
            case 28:
                return n.b();
            default:
                return BrazeProperties.addProperty$lambda$1();
        }
    }
}
