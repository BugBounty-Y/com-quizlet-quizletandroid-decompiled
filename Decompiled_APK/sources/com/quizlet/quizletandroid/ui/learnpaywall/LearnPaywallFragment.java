package com.quizlet.quizletandroid.ui.learnpaywall;

import com.quizlet.upgrade.paywall.ui.PaywallFragment;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class LearnPaywallFragment extends PaywallFragment {
    public static final String h;
    public com.onetrust.otpublishers.headless.UI.viewmodel.c f;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e g = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(k.class), new a(this, 0), new com.quizlet.login.magiclink.ui.e(this, 16), new a(this, 1));

    static {
        Intrinsics.checkNotNullExpressionValue("LearnPaywallFragment", "getSimpleName(...)");
        h = "LearnPaywallFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return h;
    }

    @Override // com.quizlet.upgrade.paywall.ui.PaywallFragment
    public final com.quizlet.upgrade.paywall.viewmodel.a R() {
        return (com.quizlet.upgrade.paywall.viewmodel.a) this.g.getValue();
    }
}
