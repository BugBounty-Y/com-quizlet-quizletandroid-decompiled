package com.braze.support;

import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class v implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ v(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return ReflectionUtils.getMethodQuietly$lambda$1();
            case 1:
                return ReflectionUtils.getDeclaredMethodQuietly$lambda$4();
            case 2:
                return ReflectionUtils.constructObjectQuietly$lambda$6();
            case 3:
                return ReflectionUtils.getMethodQuietly$lambda$0();
            case 4:
                return StringUtils.getCacheFileSuffix$lambda$1();
            case 5:
                return ValidationUtils.isValidLogPurchaseInput$lambda$3();
            case 6:
                return ValidationUtils.isValidLogPurchaseInput$lambda$1();
            case 7:
                return ValidationUtils.isValidLogCustomEventInput$lambda$8();
            case 8:
                return ValidationUtils.isValidPushStoryClickInput$lambda$11();
            case 9:
                return ValidationUtils.isValidPushStoryClickInput$lambda$10();
            case 10:
                return ValidationUtils.isValidLogPurchaseInput$lambda$5();
            case 11:
                return WebContentUtils.getLocalHtmlUrlFromRemoteUrl$lambda$0();
            case 12:
                return WebContentUtils.getLocalHtmlUrlFromRemoteUrl$lambda$4();
            case 13:
                return WebContentUtils.unpackZipIntoDirectory$lambda$6();
            case 14:
                return c.a();
            case 15:
                return d.d();
            case 16:
                return d.c();
            case 17:
                return d.b();
            case 18:
                return d.a();
            case 19:
                return j.a();
            case 20:
                return k.c();
            case 21:
                return k.b();
            case EventType.WINDOW_STATE /* 22 */:
                return n.a();
            case EventType.AUDIO /* 23 */:
                return s.a();
            case EventType.VIDEO /* 24 */:
                return com.braze.triggers.actions.c.c();
            case EventType.SUBS /* 25 */:
                return com.braze.triggers.actions.c.d();
            case EventType.CDN /* 26 */:
                return com.braze.triggers.actions.c.b();
            case 27:
                return com.braze.triggers.actions.f.b();
            case 28:
                return com.braze.triggers.config.b.b();
            default:
                return com.braze.triggers.config.c.b();
        }
    }
}
