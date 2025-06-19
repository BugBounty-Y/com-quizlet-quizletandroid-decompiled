package com.braze.managers;

import com.braze.models.Banner;
import com.braze.models.FeatureFlag;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class P implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ P(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return r.j();
            case 1:
                return r.b();
            case 2:
                return r.c();
            case 3:
                return r.e();
            case 4:
                return C1505s.a();
            case 5:
                return s0.j();
            case 6:
                return s0.h();
            case 7:
                return s0.d();
            case 8:
                return s0.e();
            case 9:
                return s0.f();
            case 10:
                return s0.b();
            case 11:
                return C1506t.g();
            case 12:
                return C1506t.i();
            case 13:
                return C1506t.a();
            case 14:
                return t0.a();
            case 15:
                return t0.b();
            case 16:
                return t0.c();
            case 17:
                return t0.d();
            case 18:
                return t0.e();
            case 19:
                return t0.f();
            case 20:
                return v.a();
            case 21:
                return y.c();
            case EventType.WINDOW_STATE /* 22 */:
                return y.d();
            case EventType.AUDIO /* 23 */:
                return y.e();
            case EventType.VIDEO /* 24 */:
                return y.b();
            case EventType.SUBS /* 25 */:
                return z.a();
            case EventType.CDN /* 26 */:
                return z.b();
            case 27:
                return Banner.forJsonPut$lambda$0();
            case 28:
                return FeatureFlag.forJsonPut$lambda$0();
            default:
                return com.braze.models.a.a();
        }
    }
}
