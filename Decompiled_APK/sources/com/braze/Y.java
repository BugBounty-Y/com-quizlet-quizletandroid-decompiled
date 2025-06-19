package com.braze;

import com.braze.configuration.BrazeConfigurationProvider;
import com.braze.configuration.CachedConfigurationProvider;
import com.braze.configuration.RuntimeAppConfigurationProvider;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class Y implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ Y(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeUser.setEmail$lambda$12();
            case 1:
                return BrazeUser.removeFromCustomAttributeArray$lambda$53();
            case 2:
                return com.braze.communication.dust.c.a();
            case 3:
                return com.braze.communication.dust.g.a();
            case 4:
                return com.braze.communication.dust.g.d();
            case 5:
                return com.braze.communication.dust.g.b();
            case 6:
                return com.braze.communication.dust.g.c();
            case 7:
                return com.braze.communication.dust.g.e();
            case 8:
                return com.braze.communication.dust.h.a();
            case 9:
                return com.braze.communication.e.a();
            case 10:
                return com.braze.communication.e.b();
            case 11:
                return com.braze.communication.g.a();
            case 12:
                return com.braze.communication.g.b();
            case 13:
                return BrazeConfigurationProvider._get_brazeApiKey_$lambda$9();
            case 14:
                return BrazeConfigurationProvider._get_brazeApiKey_$lambda$10();
            case 15:
                return BrazeConfigurationProvider._get_versionCode_$lambda$11();
            case 16:
                return BrazeConfigurationProvider._get_defaultNotificationAccentColor_$lambda$13();
            case 17:
                return BrazeConfigurationProvider._get_ephemeralEventKeys_$lambda$0();
            case 18:
                return BrazeConfigurationProvider._get_sdkFlavor_$lambda$14();
            case 19:
                return BrazeConfigurationProvider._get_brazeApiKey_$lambda$1();
            case 20:
                return BrazeConfigurationProvider._get_brazeApiKey_$lambda$2();
            case 21:
                return BrazeConfigurationProvider._get_brazeApiKey_$lambda$3();
            case EventType.WINDOW_STATE /* 22 */:
                return BrazeConfigurationProvider._get_brazeApiKey_$lambda$4();
            case EventType.AUDIO /* 23 */:
                return BrazeConfigurationProvider._get_brazeApiKey_$lambda$5();
            case EventType.VIDEO /* 24 */:
                return BrazeConfigurationProvider._get_brazeApiKey_$lambda$6();
            case EventType.SUBS /* 25 */:
                return BrazeConfigurationProvider._get_brazeApiKey_$lambda$7();
            case EventType.CDN /* 26 */:
                return BrazeConfigurationProvider._get_brazeApiKey_$lambda$8();
            case 27:
                return CachedConfigurationProvider.readResourceValue$lambda$3();
            case 28:
                return CachedConfigurationProvider.resetCache$lambda$5();
            default:
                return RuntimeAppConfigurationProvider.clearAllConfigurationValues$lambda$2();
        }
    }
}
