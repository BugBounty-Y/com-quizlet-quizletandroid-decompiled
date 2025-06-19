package com.braze.requests.framework;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import androidx.compose.animation.core.C0238e;
import com.appsflyer.AppsFlyerLib;
import com.braze.Braze;
import com.braze.enums.CardKey;
import com.braze.events.ContentCardsUpdatedEvent;
import com.braze.models.cards.Card;
import com.braze.storage.e0;
import com.braze.storage.t;
import com.braze.ui.BrazeWebViewClient;
import com.braze.ui.actions.UriAction;
import com.braze.ui.contentcards.ContentCardsFragment;
import com.braze.ui.inappmessage.BrazeInAppMessageManager;
import com.braze.ui.inappmessage.DefaultInAppMessageViewWrapper;
import com.comscore.streaming.EventType;
import com.quizlet.ads.ui.widgets.AdsCountDownButton;
import com.quizlet.edgy.ui.fragment.EdgyModalFragment;
import com.quizlet.quizletandroid.R;
import io.reactivex.rxjava3.internal.operators.maybe.w;
import java.io.File;
import java.util.Date;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class o implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ o(AdsCountDownButton adsCountDownButton, com.quizlet.ads.ui.widgets.b bVar) {
        this.a = 18;
        this.b = adsCountDownButton;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        Object obj = this.b;
        switch (this.a) {
            case 0:
                return e.a((g) obj);
            case 1:
                return f.b((com.braze.models.response.a) obj);
            case 2:
                return com.braze.requests.framework.queue.d.a((com.braze.requests.m) obj);
            case 3:
                return com.braze.requests.h.a((com.braze.requests.n) obj);
            case 4:
                return com.braze.requests.util.b.a((com.braze.requests.util.b) obj);
            case 5:
                return e0.a((e0) obj);
            case 6:
                return com.braze.storage.p.a(Boolean.TRUE, (CardKey) obj);
            case 7:
                return t.a((Map.Entry) obj);
            case 8:
                return com.braze.support.d.c((Date) obj);
            case 9:
                return com.braze.triggers.actions.f.a((com.braze.triggers.actions.f) obj);
            case 10:
                return com.braze.triggers.managers.a.a((File[]) obj);
            case 11:
                return com.braze.triggers.managers.f.e((com.braze.triggers.actions.h) obj);
            case 12:
                return BrazeWebViewClient.appendBridgeJavascript$lambda$3((BrazeWebViewClient) obj);
            case 13:
                return UriAction.getActionViewIntent$lambda$8((ResolveInfo) obj);
            case 14:
                return ContentCardsFragment.contentCardsUpdate$lambda$10((ContentCardsUpdatedEvent) obj);
            case 15:
                return BrazeInAppMessageManager.resetAfterInAppMessageClose$lambda$36((Integer) obj);
            case 16:
                return DefaultInAppMessageViewWrapper.closeInAppMessageView$lambda$25((DefaultInAppMessageViewWrapper) obj);
            case 17:
                ((com.perimeterx.mobile_sdk.doctor_app.ui.k) obj).getContext().startActivity(new Intent("android.intent.action.VIEW", Uri.parse("https://docs.perimeterx.com/pxconsole/docs/sdk-android")));
                return Unit.a;
            case 18:
                int i = AdsCountDownButton.B;
                ((AdsCountDownButton) obj).setState(new com.quizlet.ads.ui.widgets.c());
                return Unit.a;
            case 19:
                com.quizlet.analytics.marketing.appsflyer.e eVar = (com.quizlet.analytics.marketing.appsflyer.e) ((com.quizlet.data.repository.classfolder.e) obj).c;
                AppsFlyerLib appsFlyerLib = AppsFlyerLib.getInstance();
                Intrinsics.checkNotNullExpressionValue(appsFlyerLib, "getInstance(...)");
                boolean z = com.quizlet.analytics.marketing.appsflyer.e.b;
                Context context = eVar.a;
                if (!z) {
                    com.quizlet.analytics.marketing.appsflyer.e.b = true;
                    appsFlyerLib.start(context);
                } else if (appsFlyerLib.isStopped()) {
                    appsFlyerLib.stop(false, context);
                }
                return Unit.a;
            case 20:
                return Float.valueOf(((Number) ((C0238e) obj).d()).floatValue());
            case 21:
                return ((com.quizlet.baserecyclerview.c) obj).d();
            case EventType.WINDOW_STATE /* 22 */:
                return (w) obj;
            case EventType.AUDIO /* 23 */:
                return (io.reactivex.rxjava3.internal.operators.flowable.b) obj;
            case EventType.VIDEO /* 24 */:
                com.quizlet.quizletandroid.braze.data.a aVar = (com.quizlet.quizletandroid.braze.data.a) ((com.quizlet.data.repository.activitycenter.b) obj).b;
                aVar.e = new io.reactivex.rxjava3.subjects.r();
                aVar.c.getClass();
                long jCurrentTimeMillis = System.currentTimeMillis() - aVar.d;
                long j = com.quizlet.quizletandroid.braze.data.a.f;
                Braze braze = aVar.a;
                if (jCurrentTimeMillis > j) {
                    braze.removeSingleSubscription(aVar, ContentCardsUpdatedEvent.class);
                    braze.subscribeToContentCardsUpdates(aVar);
                    braze.requestContentCardsRefresh(false);
                } else {
                    List<Card> cachedContentCards = braze.getCachedContentCards();
                    aVar.e.onSuccess(Integer.valueOf(cachedContentCards != null ? aVar.a(cachedContentCards) : 0));
                }
                io.reactivex.rxjava3.subjects.r rVar = aVar.e;
                com.quizlet.eventlogger.e eVar2 = new com.quizlet.eventlogger.e(aVar, 17);
                rVar.getClass();
                w wVar = new w(2, rVar, eVar2);
                Intrinsics.checkNotNullExpressionValue(wVar, "doOnDispose(...)");
                return wVar;
            case EventType.SUBS /* 25 */:
                return (io.reactivex.rxjava3.internal.operators.single.g) obj;
            case EventType.CDN /* 26 */:
                ((com.quizlet.db.token.c) obj).getClass();
                return Cipher.getInstance("AES/GCM/NoPadding");
            case 27:
                String str = EdgyModalFragment.L;
                return ((EdgyModalFragment) obj).getString(R.string.edgy_flow_add_courses_modal_title);
            case 28:
                return Boolean.valueOf(!((com.quizlet.explanations.questiondetail.recyclerview.g) obj).e());
            default:
                com.quizlet.data.repository.explanations.question.a aVar2 = (com.quizlet.data.repository.explanations.question.a) obj;
                return ((com.quizlet.growthbook.e) ((com.quizlet.infra.contracts.growthbook.a) aVar2.a)).a((String) aVar2.b);
        }
    }

    public /* synthetic */ o(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }
}
