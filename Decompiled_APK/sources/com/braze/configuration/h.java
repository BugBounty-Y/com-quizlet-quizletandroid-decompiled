package com.braze.configuration;

import com.braze.coroutine.BrazeCoroutineScope;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class h implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ h(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return e.b();
            case 1:
                return BrazeCoroutineScope.cancelChildren$lambda$1();
            case 2:
                return com.braze.coroutine.f.b();
            case 3:
                return com.braze.dispatch.c.a();
            case 4:
                return com.braze.dispatch.c.b();
            case 5:
                return com.braze.dispatch.e.a();
            case 6:
                return com.braze.dispatch.f.a();
            case 7:
                return com.braze.dispatch.f.j();
            case 8:
                return com.braze.dispatch.f.g();
            case 9:
                return com.braze.dispatch.f.h();
            case 10:
                return com.braze.dispatch.f.d();
            case 11:
                return com.braze.dispatch.f.e();
            case 12:
                return com.braze.dispatch.g.a();
            case 13:
                return com.braze.dispatch.h.d();
            case 14:
                return com.braze.dispatch.h.c();
            case 15:
                return com.braze.dispatch.h.b();
            case 16:
                return com.braze.dispatch.h.a();
            case 17:
                return com.braze.events.a.b();
            case 18:
                return com.braze.events.a.e();
            case 19:
                return com.braze.events.a.c();
            case 20:
                return com.braze.events.a.d();
            case 21:
                return com.braze.events.a.V();
            case EventType.WINDOW_STATE /* 22 */:
                return com.braze.events.a.W();
            case EventType.AUDIO /* 23 */:
                return com.braze.events.a.n();
            case EventType.VIDEO /* 24 */:
                return com.braze.events.a.a();
            case EventType.SUBS /* 25 */:
                return com.braze.events.a.d0();
            case EventType.CDN /* 26 */:
                return com.braze.events.a.e0();
            case 27:
                return com.braze.events.a.M();
            case 28:
                return com.braze.events.a.N();
            default:
                return com.braze.events.a.u();
        }
    }
}
