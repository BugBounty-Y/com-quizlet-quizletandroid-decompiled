package com.onetrust.otpublishers.headless.UI.fragment;

import android.app.Application;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.onetrust.otpublishers.headless.UI.fragment.e, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4061e extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C4063g b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C4061e(C4063g c4063g, int i) {
        super(0);
        this.a = i;
        this.b = c4063g;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return this.b;
            default:
                C4063g c4063g = this.b;
                Application application = c4063g.requireActivity().getApplication();
                Intrinsics.checkNotNullExpressionValue(application, "requireActivity().application");
                return new com.onetrust.otpublishers.headless.UI.viewmodel.a(application, c4063g.q);
        }
    }
}
