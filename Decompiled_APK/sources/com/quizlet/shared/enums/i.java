package com.quizlet.shared.enums;

import kotlin.jvm.functions.Function0;
import kotlinx.serialization.internal.AbstractC5047c0;

/* loaded from: classes3.dex */
public final class i extends kotlin.jvm.internal.r implements Function0 {
    public static final i b = new i(0, 0);
    public static final i c = new i(0, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ i(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return AbstractC5047c0.e("com.quizlet.shared.enums.SelfIdentifiedUserType", j.values());
            default:
                return AbstractC5047c0.e("com.quizlet.shared.enums.UserUpgradeType", u.values());
        }
    }
}
