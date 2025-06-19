package com.braze.requests;

import com.braze.storage.AbstractC1515b;
import com.braze.storage.e0;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class y implements Function0 {
    public final /* synthetic */ int a;

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return b.k();
            case 1:
                return d.b();
            case 2:
                return d.d();
            case 3:
                return e.l();
            case 4:
                return f.l();
            case 5:
                return f.m();
            case 6:
                return com.braze.requests.framework.d.a();
            case 7:
                return com.braze.requests.framework.d.b();
            case 8:
                return com.braze.requests.framework.d.c();
            case 9:
                return com.braze.requests.framework.g.h();
            case 10:
                return com.braze.requests.framework.g.f();
            case 11:
                return com.braze.requests.framework.g.b();
            case 12:
                return com.braze.requests.framework.g.c();
            case 13:
                return com.braze.requests.framework.g.d();
            case 14:
                return g.l();
            case 15:
                return i.l();
            case 16:
                return i.n();
            case 17:
                return i.m();
            case 18:
                return j.d();
            case 19:
                return q.d();
            case 20:
                return r.l();
            case 21:
                return r.m();
            case EventType.WINDOW_STATE /* 22 */:
                return v.l();
            case EventType.AUDIO /* 23 */:
                return w.d();
            case EventType.VIDEO /* 24 */:
                return x.l();
            case EventType.SUBS /* 25 */:
                return AbstractC1515b.b();
            case EventType.CDN /* 26 */:
                return e0.Q();
            case 27:
                return e0.N();
            case 28:
                return e0.O();
            default:
                return e0.R();
        }
    }
}
