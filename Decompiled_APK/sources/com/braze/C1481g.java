package com.braze;

import com.braze.models.inappmessage.InAppMessageHtmlBase;
import com.braze.push.BrazeFirebaseMessagingService;
import com.braze.push.BrazeNotificationUtils;
import com.braze.push.BrazePushReceiver;
import com.braze.support.StringUtils;
import com.braze.support.WebContentUtils;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* renamed from: com.braze.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1481g implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ String c;

    public /* synthetic */ C1481g(int i, String str, String str2) {
        this.a = i;
        this.b = str;
        this.c = str2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Braze.addSerializedCardJsonToStorage$lambda$178(this.b, this.c);
            case 1:
                return Braze.changeUser$lambda$138$lambda$136(this.b, this.c);
            case 2:
                return Braze.addSerializedCardJsonToStorage$lambda$180$lambda$179(this.b, this.c);
            case 3:
                return Braze.logPushStoryPageClicked$lambda$68(this.b, this.c);
            case 4:
                return com.braze.communication.dust.h.a(this.b, this.c);
            case 5:
                return com.braze.communication.dust.h.b(this.b, this.c);
            case 6:
                return com.braze.images.a.a(this.b, this.c);
            case 7:
                return com.braze.images.a.d(this.b, this.c);
            case 8:
                return com.braze.images.a.b(this.b, this.c);
            case 9:
                return com.braze.images.a.c(this.b, this.c);
            case 10:
                return InAppMessageHtmlBase.logButtonClick$lambda$5(this.b, this.c);
            case 11:
                return com.braze.models.outgoing.event.a.r(this.b, this.c);
            case 12:
                return com.braze.models.outgoing.event.a.t(this.b, this.c);
            case 13:
                return com.braze.models.outgoing.event.a.n(this.b, this.c);
            case 14:
                return com.braze.models.outgoing.event.a.j(this.b, this.c);
            case 15:
                return com.braze.models.outgoing.event.a.l(this.b, this.c);
            case 16:
                return com.braze.models.outgoing.event.a.b(this.b, this.c);
            case 17:
                return com.braze.models.outgoing.event.a.f(this.b, this.c);
            case 18:
                return com.braze.models.outgoing.event.a.p(this.b, this.c);
            case 19:
                return BrazeFirebaseMessagingService.Companion.handleBrazeRemoteMessage$lambda$5(this.b, this.c);
            case 20:
                return BrazeNotificationUtils.handleContentCardsSerializedCardIfPresent$lambda$73(this.b, this.c);
            case 21:
                return BrazePushReceiver.Companion.handleAdmRegistrationIntent$lambda$7(this.b, this.c);
            case EventType.WINDOW_STATE /* 22 */:
                return com.braze.storage.p.a(this.b, this.c);
            case EventType.AUDIO /* 23 */:
                return com.braze.storage.x.a(this.b, this.c);
            case EventType.VIDEO /* 24 */:
                return StringUtils.getCacheFileSuffix$lambda$2(this.b, this.c);
            case EventType.SUBS /* 25 */:
                return WebContentUtils.getLocalHtmlUrlFromRemoteUrl$lambda$1(this.b, this.c);
            case EventType.CDN /* 26 */:
                return WebContentUtils.getLocalHtmlUrlFromRemoteUrl$lambda$3(this.b, this.c);
            case 27:
                return WebContentUtils.replacePrefetchedUrlsWithLocalAssets$lambda$13(this.b, this.c);
            case 28:
                return com.braze.triggers.managers.a.b(this.b, this.c);
            default:
                return com.braze.triggers.managers.a.a(this.b, this.c);
        }
    }
}
