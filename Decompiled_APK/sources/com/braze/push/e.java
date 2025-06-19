package com.braze.push;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final /* synthetic */ class e implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Integer b;

    public /* synthetic */ e(int i, Integer num) {
        this.a = i;
        this.b = num;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return BrazeNotificationUtils.getNotificationId$lambda$17(this.b);
            case 1:
                return BrazeNotificationUtils.getNotificationPriority$lambda$22$lambda$21(this.b);
            default:
                return BrazeNotificationUtils.setVisibilityIfPresentAndSupported$lambda$57(this.b);
        }
    }
}
