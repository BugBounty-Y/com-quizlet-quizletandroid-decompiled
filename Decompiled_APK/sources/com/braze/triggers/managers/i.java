package com.braze.triggers.managers;

import com.braze.ui.BrazeDeeplinkHandler;
import com.braze.ui.BrazeWebViewActivity;
import com.braze.ui.BrazeWebViewClient;
import com.braze.ui.UserJavascriptInterfaceBase;
import com.braze.ui.actions.NewsfeedAction;
import com.braze.ui.actions.UriAction;
import com.braze.ui.actions.brazeactions.BrazeActionParser;
import com.braze.ui.actions.brazeactions.steps.BaseBrazeActionStep$Companion$runOnUser$1;
import com.braze.ui.contentcards.BrazeContentCardUtils;
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
                return a.a();
            case 1:
                return c.a();
            case 2:
                return f.c();
            case 3:
                return f.d();
            case 4:
                return f.e();
            case 5:
                return f.f();
            case 6:
                return f.h();
            case 7:
                return f.l();
            case 8:
                return f.m();
            case 9:
                return f.i();
            case 10:
                return f.j();
            case 11:
                return g.b();
            case 12:
                return com.braze.triggers.utils.c.c();
            case 13:
                return com.braze.triggers.utils.c.a();
            case 14:
                return com.braze.triggers.utils.c.b();
            case 15:
                return BrazeDeeplinkHandler.createUriActionFromUrlString$lambda$0();
            case 16:
                return BrazeDeeplinkHandler.createUriActionFromUrlString$lambda$1();
            case 17:
                return BrazeWebViewActivity.C15221.onRenderProcessGone$lambda$1();
            case 18:
                return BrazeWebViewClient.markPageFinished$lambda$5$lambda$4();
            case 19:
                return BrazeWebViewClient.onRenderProcessGone$lambda$14();
            case 20:
                return BrazeWebViewClient.onPageFinished$lambda$2$lambda$1();
            case 21:
                return UserJavascriptInterfaceBase.parseStringArrayFromJsonString$lambda$34();
            case EventType.WINDOW_STATE /* 22 */:
                return NewsfeedAction.execute$lambda$0();
            case EventType.AUDIO /* 23 */:
                return UriAction.getIntentArrayWithConfiguredBackStack$lambda$9();
            case EventType.VIDEO /* 24 */:
                return UriAction.getIntentArrayWithConfiguredBackStack$lambda$13();
            case EventType.SUBS /* 25 */:
                return UriAction.openUriWithWebViewActivity$lambda$3();
            case EventType.CDN /* 26 */:
                return UriAction.openUriWithWebViewActivityFromPush$lambda$5();
            case 27:
                return BrazeActionParser.execute$lambda$1();
            case 28:
                return BaseBrazeActionStep$Companion$runOnUser$1.onError$lambda$0();
            default:
                return BrazeContentCardUtils.getUriActionForCard$lambda$2();
        }
    }
}
