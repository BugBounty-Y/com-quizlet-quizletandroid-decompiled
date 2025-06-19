package com.braze;

import com.braze.models.outgoing.BrazeProperties;
import kotlin.jvm.functions.Function0;

/* renamed from: com.braze.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1479e implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ BrazeProperties c;

    public /* synthetic */ C1479e(String str, BrazeProperties brazeProperties, int i) {
        this.a = i;
        this.b = str;
        this.c = brazeProperties;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Braze.logCustomEvent$lambda$50$lambda$48(this.b, this.c);
            case 1:
                return Braze.logCustomEvent$lambda$50$lambda$45(this.b, this.c);
            default:
                return com.braze.models.outgoing.event.a.b(this.b, this.c);
        }
    }
}
