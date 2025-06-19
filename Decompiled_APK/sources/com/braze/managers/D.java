package com.braze.managers;

import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class D implements Function0 {
    public final /* synthetic */ int a;

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return b0.h();
            case 1:
                return b0.i();
            case 2:
                return Boolean.valueOf(b0.d());
            case 3:
                return b0.e();
            case 4:
                return b0.b();
            case 5:
                return b0.j();
            case 6:
                return b0.k();
            case 7:
                return C1493f.b(null);
            case 8:
                return C1494g.c(null);
            case 9:
                return C1495h.f();
            case 10:
                return C1495h.d();
            case 11:
                return C1495h.l();
            case 12:
                return C1495h.k();
            case 13:
                return C1495h.b();
            case 14:
                return C1495h.c();
            case 15:
                return C1495h.h();
            case 16:
                return C1495h.i();
            case 17:
                return C1495h.b((AbstractC1491d) null);
            case 18:
                return C1495h.g();
            case 19:
                return C1496i.a();
            case 20:
                return C1496i.b();
            case 21:
                return C1498k.c();
            case EventType.WINDOW_STATE /* 22 */:
                return C1498k.b(null);
            case EventType.AUDIO /* 23 */:
                return C1498k.e();
            case EventType.VIDEO /* 24 */:
                return C1498k.f();
            case EventType.SUBS /* 25 */:
                return C1498k.a();
            case EventType.CDN /* 26 */:
                return C1498k.b();
            case 27:
                return l0.a();
            case 28:
                return C1500m.B();
            default:
                return C1500m.s();
        }
    }
}
