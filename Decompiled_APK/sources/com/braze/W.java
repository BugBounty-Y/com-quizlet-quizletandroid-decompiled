package com.braze;

import com.braze.configuration.BrazeConfigurationProvider;
import com.braze.images.DefaultBrazeImageLoader;
import com.braze.managers.BrazeGeofenceManager;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class W implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;

    public /* synthetic */ W(String str, int i) {
        this.a = i;
        this.b = str;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeUser.setCustomUserAttribute$lambda$44(this.b);
            case 1:
                return BrazeUser._set_userId_$lambda$1(this.b);
            case 2:
                return BrazeUser.setCustomUserAttribute$lambda$43(this.b);
            case 3:
                return BrazeUser.removeFromSubscriptionGroup$lambda$32(this.b);
            case 4:
                return BrazeUser.setCustomAttributeArray$lambda$55(this.b);
            case 5:
                return BrazeUser.setEmail$lambda$15$lambda$14(this.b);
            case 6:
                return BrazeUser.setEmail$lambda$16(this.b);
            case 7:
                return com.braze.analytics.b.e(this.b);
            case 8:
                return com.braze.analytics.b.f(this.b);
            case 9:
                return com.braze.communication.dust.g.a(this.b);
            case 10:
                return com.braze.communication.dust.h.d(this.b);
            case 11:
                return com.braze.communication.dust.h.b(this.b);
            case 12:
                return com.braze.communication.dust.h.c(this.b);
            case 13:
                return com.braze.communication.dust.h.a(this.b);
            case 14:
                return BrazeConfigurationProvider._get_applicationIconResourceId_$lambda$12(this.b);
            case 15:
                return com.braze.configuration.e.a(this.b);
            case 16:
                return com.braze.configuration.e.c(this.b);
            case 17:
                return DefaultBrazeImageLoader.putBitmapIntoCache$lambda$23$lambda$22(this.b);
            case 18:
                return DefaultBrazeImageLoader.getBitmapFromDiskCache$lambda$19$lambda$17(this.b);
            case 19:
                return DefaultBrazeImageLoader.getBitmapFromDiskCache$lambda$19$lambda$18(this.b);
            case 20:
                return DefaultBrazeImageLoader.renderUrlIntoView$lambda$2(this.b);
            case 21:
                return DefaultBrazeImageLoader.getBitmapFromUrl$lambda$11(this.b);
            case EventType.WINDOW_STATE /* 22 */:
                return DefaultBrazeImageLoader.getBitmapFromCache$lambda$15$lambda$14(this.b);
            case EventType.AUDIO /* 23 */:
                return DefaultBrazeImageLoader.getBitmapFromCache$lambda$16(this.b);
            case EventType.VIDEO /* 24 */:
                return DefaultBrazeImageLoader.putBitmapIntoCache$lambda$20(this.b);
            case EventType.SUBS /* 25 */:
                return DefaultBrazeImageLoader.putBitmapIntoCache$lambda$21(this.b);
            case EventType.CDN /* 26 */:
                return com.braze.images.g.a(this.b);
            case 27:
                return BrazeGeofenceManager.Companion.retrieveBrazeGeofencesFromLocalStorage$lambda$5(this.b);
            case 28:
                return BrazeGeofenceManager.Companion.retrieveBrazeGeofencesFromLocalStorage$lambda$7(this.b);
            default:
                return BrazeGeofenceManager.Companion.retrieveBrazeGeofencesFromLocalStorage$lambda$6(this.b);
        }
    }
}
