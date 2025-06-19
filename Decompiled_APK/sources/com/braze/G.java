package com.braze;

import com.braze.events.InAppMessageEvent;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class G implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Braze b;
    public final /* synthetic */ InAppMessageEvent c;

    public /* synthetic */ G(Braze braze, InAppMessageEvent inAppMessageEvent, int i) {
        this.a = i;
        this.b = braze;
        this.c = inAppMessageEvent;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Braze.reenqueueInAppMessage$lambda$199(this.b, this.c);
            default:
                return Braze.retryInAppMessage$lambda$197(this.b, this.c);
        }
    }
}
