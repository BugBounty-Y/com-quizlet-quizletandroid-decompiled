package com.braze.managers;

import com.braze.models.inappmessage.InAppMessageHtmlBase;
import com.braze.models.outgoing.BrazeProperties;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class C implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;

    public /* synthetic */ C(String str, int i) {
        this.a = i;
        this.b = str;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return a0.a(this.b);
            case 1:
                return a0.b(this.b);
            case 2:
                return b0.b(this.b);
            case 3:
                return b0.d(this.b);
            case 4:
                return C1495h.d(this.b);
            case 5:
                return C1495h.e(this.b);
            case 6:
                return C1496i.c(this.b);
            case 7:
                return C1496i.d(this.b);
            case 8:
                return C1496i.b(this.b);
            case 9:
                return i0.b(this.b);
            case 10:
                return k0.b(this.b);
            case 11:
                return C1500m.b(this.b);
            case 12:
                return C1506t.a(this.b);
            case 13:
                return y.b(this.b);
            case 14:
                return InAppMessageHtmlBase.logButtonClick$lambda$0(this.b);
            case 15:
                return com.braze.models.inappmessage.b.a(this.b);
            case 16:
                return BrazeProperties.addProperty$lambda$0(this.b);
            case 17:
                return com.braze.models.outgoing.event.a.n(this.b);
            case 18:
                return com.braze.models.outgoing.event.a.d(this.b);
            case 19:
                return com.braze.models.outgoing.event.a.l(this.b);
            case 20:
                return com.braze.models.outgoing.event.a.f(this.b);
            case 21:
                return com.braze.models.outgoing.event.a.h(this.b);
            case EventType.WINDOW_STATE /* 22 */:
                return com.braze.models.outgoing.event.a.p(this.b);
            case EventType.AUDIO /* 23 */:
                return com.braze.models.outgoing.event.a.j(this.b);
            case EventType.VIDEO /* 24 */:
                return com.braze.n0.a(this.b);
            case EventType.SUBS /* 25 */:
                return com.braze.requests.b.a(this.b);
            case EventType.CDN /* 26 */:
                return com.braze.requests.d.a(this.b);
            case 27:
                return com.braze.requests.l.b(this.b);
            case 28:
                return com.braze.storage.e0.a(this.b, "36.0.0");
            default:
                return com.braze.storage.f0.a(this.b);
        }
    }
}
