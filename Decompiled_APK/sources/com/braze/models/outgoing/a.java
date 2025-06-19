package com.braze.models.outgoing;

import com.braze.models.IBrazeLocation;
import com.braze.models.push.BrazeNotificationPayload;
import com.braze.models.response.m;
import com.braze.push.support.HtmlUtils;
import com.braze.requests.C1512a;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeProperties.clone$lambda$2();
            case 1:
                return d.a();
            case 2:
                return d.b();
            case 3:
                return com.braze.models.outgoing.event.a.q("feed_displayed");
            case 4:
                return com.braze.models.outgoing.event.a.c();
            case 5:
                return com.braze.models.outgoing.event.a.b((IBrazeLocation) null);
            case 6:
                return com.braze.models.outgoing.event.a.b();
            case 7:
                return com.braze.models.outgoing.event.b.b();
            case 8:
                return h.b();
            case 9:
                return BrazeNotificationPayload.Companion.getTemplateFieldAtIndex$lambda$1();
            case 10:
                return BrazeNotificationPayload.Companion.getTemplateFieldAtIndex$lambda$0();
            case 11:
                return m.d();
            case 12:
                return m.i();
            case 13:
                return m.h();
            case 14:
                return m.f();
            case 15:
                return m.e();
            case 16:
                return m.b();
            case 17:
                return m.c();
            case 18:
                return m.a();
            case 19:
                return m.g();
            case 20:
                return HtmlUtils.getHtmlSpannedTextIfEnabled$lambda$0();
            case 21:
                return C1512a.l();
            case EventType.WINDOW_STATE /* 22 */:
                return C1512a.m();
            case EventType.AUDIO /* 23 */:
                return C1512a.g();
            case EventType.VIDEO /* 24 */:
                return com.braze.requests.b.d();
            case EventType.SUBS /* 25 */:
                return com.braze.requests.b.f();
            case EventType.CDN /* 26 */:
                return com.braze.requests.b.g();
            case 27:
                return com.braze.requests.b.h();
            case 28:
                return com.braze.requests.b.i();
            default:
                return com.braze.requests.b.j();
        }
    }
}
