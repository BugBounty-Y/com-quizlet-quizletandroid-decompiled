package com.braze.managers;

import com.braze.events.BrazeUserChangeEvent;
import com.braze.ui.inappmessage.BrazeInAppMessageManager;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class G implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ BrazeUserChangeEvent b;

    public /* synthetic */ G(BrazeUserChangeEvent brazeUserChangeEvent, int i) {
        this.a = i;
        this.b = brazeUserChangeEvent;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return C1495h.a(this.b);
            case 1:
                return C1495h.b(this.b);
            default:
                return BrazeInAppMessageManager.createBrazeUserChangeEventSubscriber$lambda$57$lambda$54(this.b);
        }
    }
}
