package com.onetrust.otpublishers.headless.UI.fragment;

import android.app.Application;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class C extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ D b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C(D d, int i) {
        super(0);
        this.a = i;
        this.b = d;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return this.b;
            default:
                Application application = this.b.requireActivity().getApplication();
                Intrinsics.checkNotNullExpressionValue(application, "requireActivity().application");
                return new com.onetrust.otpublishers.headless.UI.viewmodel.c(application, 1);
        }
    }
}
