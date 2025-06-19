package com.braze.events;

import com.braze.images.DefaultBrazeImageLoader;
import com.braze.managers.BrazeGeofenceManager;
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
                return a.m();
            case 1:
                return a.b0();
            case 2:
                return a.f();
            case 3:
                return a.g();
            case 4:
                return a.h();
            case 5:
                return a.i();
            case 6:
                return a.j();
            case 7:
                return a.k();
            case 8:
                return a.l();
            case 9:
                return a.S();
            case 10:
                return a.T();
            case 11:
                return a.J();
            case 12:
                return a.K();
            case 13:
                return a.P();
            case 14:
                return a.Q();
            case 15:
                return a.Y();
            case 16:
                return a.Z();
            case 17:
                return d.b();
            case 18:
                return com.braze.events.internal.dispatchmanager.a.a();
            case 19:
                return DefaultBrazeImageLoader.renderUrlIntoView$lambda$1();
            case 20:
                return DefaultBrazeImageLoader.getBitmapFromUrl$lambda$8();
            case 21:
                return DefaultBrazeImageLoader.getBitmapFromUrl$lambda$10();
            case EventType.WINDOW_STATE /* 22 */:
                return com.braze.images.d.a();
            case EventType.AUDIO /* 23 */:
                return com.braze.images.d.b();
            case EventType.VIDEO /* 24 */:
                return com.braze.images.d.c();
            case EventType.SUBS /* 25 */:
                return BrazeGeofenceManager._init_$lambda$0();
            case EventType.CDN /* 26 */:
                return BrazeGeofenceManager.setUpGeofences$lambda$13();
            case 27:
                return BrazeGeofenceManager.tearDownGeofences$lambda$15();
            case 28:
                return BrazeGeofenceManager.tearDownGeofences$lambda$16();
            default:
                return BrazeGeofenceManager.tearDownGeofences$lambda$18$lambda$17();
        }
    }
}
