package com.braze;

import com.braze.managers.C1497j;
import com.braze.support.ValidationUtils;
import com.braze.support.WebContentUtils;
import com.braze.ui.support.UriUtils;
import java.util.Map;
import kotlin.jvm.functions.Function0;

/* renamed from: com.braze.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1480f implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ kotlin.jvm.internal.J b;

    public /* synthetic */ C1480f(kotlin.jvm.internal.J j, int i) {
        this.a = i;
        this.b = j;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Braze.logCustomEvent$lambda$50$lambda$49(this.b);
            case 1:
                return Braze.logCustomEvent$lambda$50$lambda$46(this.b);
            case 2:
                return Braze.logCustomEvent$lambda$50$lambda$47(this.b);
            case 3:
                return com.braze.communication.dust.g.a(this.b);
            case 4:
                return com.braze.communication.dust.h.a(this.b);
            case 5:
                return com.braze.communication.dust.h.b(this.b);
            case 6:
                return C1497j.a(this.b);
            case 7:
                return com.braze.storage.p.a(this.b);
            case 8:
                return ValidationUtils.ensureBrazeFieldLength$lambda$0(this.b);
            case 9:
                return WebContentUtils.unpackZipIntoDirectory$lambda$10$lambda$9(this.b);
            case 10:
                return WebContentUtils.unpackZipIntoDirectory$lambda$10$lambda$7(this.b);
            case 11:
                return UriUtils.getQueryParameters$lambda$0(this.b);
            case 12:
                return UriUtils.getQueryParameters$lambda$2(this.b);
            default:
                return (Map) this.b.a;
        }
    }
}
