package com.braze.storage;

import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class B implements Function0 {
    public final /* synthetic */ int a;

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return e0.b();
            case 1:
                return e0.c();
            case 2:
                return e0.x();
            case 3:
                return e0.h();
            case 4:
                return e0.P();
            case 5:
                return g0.a();
            case 6:
                return g0.b();
            case 7:
                return g0.d();
            case 8:
                return h0.e();
            case 9:
                return h0.f();
            case 10:
                return h0.k();
            case 11:
                return h0.i();
            case 12:
                return h0.m();
            case 13:
                return h0.d();
            case 14:
                return p.d();
            case 15:
                return p.c();
            case 16:
                return p.b();
            case 17:
                return q.a();
            case 18:
                return q.b();
            case 19:
                return q.c();
            case 20:
                return q.d();
            case 21:
                return r.f();
            case EventType.WINDOW_STATE /* 22 */:
                return r.d();
            case EventType.AUDIO /* 23 */:
                return r.h();
            case EventType.VIDEO /* 24 */:
                return r.i();
            case EventType.SUBS /* 25 */:
                return r.j();
            case EventType.CDN /* 26 */:
                return s.e();
            case 27:
                return s.b();
            case 28:
                return s.a();
            default:
                return s.d();
        }
    }
}
