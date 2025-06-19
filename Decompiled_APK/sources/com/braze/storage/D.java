package com.braze.storage;

import com.braze.support.BrazeFileUtils;
import com.braze.support.BrazeImageUtils;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import com.braze.support.JsonUtils;
import com.braze.support.PermissionUtils;
import com.braze.support.ReflectionUtils;
import com.comscore.streaming.EventType;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class D implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;

    public /* synthetic */ D(String str, int i) {
        this.a = i;
        this.b = str;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return h0.a(this.b);
            case 1:
                return j.a(this.b);
            case 2:
                return p.c(this.b);
            case 3:
                return p.i(this.b);
            case 4:
                return p.j(this.b);
            case 5:
                return p.b(this.b);
            case 6:
                return p.h(this.b);
            case 7:
                return p.l(this.b);
            case 8:
                return p.m(this.b);
            case 9:
                return p.k(this.b);
            case 10:
                return p.e(this.b);
            case 11:
                return p.f(this.b);
            case 12:
                return u.a(this.b);
            case 13:
                return v.a(this.b);
            case 14:
                return x.a(this.b);
            case 15:
                return y.b(this.b);
            case 16:
                return z.a(this.b);
            case 17:
                return BrazeFileUtils.downloadFileToPath$lambda$11(this.b);
            case 18:
                return BrazeFileUtils.downloadFileToPath$lambda$4(this.b);
            case 19:
                return BrazeImageUtils.getRemoteBitmap$lambda$17(this.b);
            case 20:
                return BrazeLogger.d$lambda$3(this.b);
            case 21:
                return BrazeLogger.v$lambda$2(this.b);
            case EventType.WINDOW_STATE /* 22 */:
                return BrazeLogger.w$lambda$5(this.b);
            case EventType.AUDIO /* 23 */:
                return BrazeLogger.i$lambda$4(this.b);
            case EventType.VIDEO /* 24 */:
                return BrazeLogger.e$lambda$6(this.b);
            case EventType.SUBS /* 25 */:
                return DateTimeUtils.parseDate$lambda$2(this.b);
            case EventType.CDN /* 26 */:
                return JsonUtils.mergeJsonObjects$lambda$3$lambda$2(this.b);
            case 27:
                return JsonUtils.mergeJsonObjects$lambda$5$lambda$4(this.b);
            case 28:
                return PermissionUtils.hasPermission$lambda$0(this.b);
            default:
                return ReflectionUtils.getDeclaredMethodQuietly$lambda$3(this.b);
        }
    }
}
