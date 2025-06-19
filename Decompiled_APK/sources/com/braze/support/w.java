package com.braze.support;

import com.braze.ui.BrazeWebViewActivity;
import com.braze.ui.BrazeWebViewClient;
import com.braze.ui.JavascriptInterfaceBase;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class w implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;

    public /* synthetic */ w(String str, int i) {
        this.a = i;
        this.b = str;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return ValidationUtils.isValidLogCustomEventInput$lambda$9(this.b);
            case 1:
                return ValidationUtils.isValidLogPurchaseInput$lambda$2(this.b);
            case 2:
                return ValidationUtils.isValidLogPurchaseInput$lambda$4(this.b);
            case 3:
                return WebContentUtils.getLocalHtmlUrlFromRemoteUrl$lambda$5(this.b);
            case 4:
                return WebContentUtils.getLocalHtmlUrlFromRemoteUrl$lambda$2(this.b);
            case 5:
                return WebContentUtils.replacePrefetchedUrlsWithLocalAssets$lambda$12(this.b);
            case 6:
                return c.a(this.b);
            case 7:
                return d.b(this.b);
            case 8:
                return d.a(this.b);
            case 9:
                return f.a(this.b);
            case 10:
                return l.b(this.b);
            case 11:
                return com.braze.triggers.managers.a.c(this.b);
            case 12:
                return com.braze.triggers.managers.a.a(this.b);
            case 13:
                return com.braze.triggers.managers.b.c(this.b);
            case 14:
                return com.braze.triggers.managers.b.d(this.b);
            case 15:
                return com.braze.triggers.managers.b.e(this.b);
            case 16:
                return com.braze.triggers.managers.b.b(this.b);
            case 17:
                return com.braze.triggers.managers.b.a(this.b);
            case 18:
                return com.braze.triggers.managers.f.a(this.b);
            case 19:
                return com.braze.triggers.managers.g.c(this.b);
            case 20:
                return com.braze.triggers.managers.g.a(this.b);
            case 21:
                return com.braze.triggers.managers.g.b(this.b);
            case EventType.WINDOW_STATE /* 22 */:
                return com.braze.triggers.utils.c.a(this.b);
            case EventType.AUDIO /* 23 */:
                return com.braze.triggers.utils.c.c(this.b);
            case EventType.VIDEO /* 24 */:
                return com.braze.triggers.utils.c.b(this.b);
            case EventType.SUBS /* 25 */:
                return BrazeWebViewActivity.C15221.handleUrlOverride$lambda$0(this.b);
            case EventType.CDN /* 26 */:
                return BrazeWebViewClient.handleUrlOverride$lambda$7$lambda$6(this.b);
            case 27:
                return JavascriptInterfaceBase.parseProperties$lambda$2(this.b);
            case 28:
                return JavascriptInterfaceBase.logPurchaseWithJSON$lambda$0(this.b);
            default:
                return JavascriptInterfaceBase.logPurchaseWithJSON$lambda$1(this.b);
        }
    }
}
