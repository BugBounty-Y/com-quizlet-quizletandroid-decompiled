package com.braze;

import com.braze.events.InAppMessageEvent;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class F implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ InAppMessageEvent b;

    public /* synthetic */ F(InAppMessageEvent inAppMessageEvent, int i) {
        this.a = i;
        this.b = inAppMessageEvent;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Braze.reenqueueInAppMessage$lambda$198(this.b);
            default:
                return Braze.retryInAppMessage$lambda$196(this.b);
        }
    }
}
