package com.quizlet.search;

import android.content.Context;
import android.view.View;
import androidx.compose.ui.platform.ComposeView;
import androidx.fragment.app.Fragment;
import com.quizlet.upgrade.paywall.ui.PaywallFragment;
import com.quizlet.upgrade.ui.confirmation.UpgradeConfirmationFragment;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements androidx.viewbinding.a {
    public final /* synthetic */ int a;
    public final /* synthetic */ Fragment b;

    public /* synthetic */ b(Fragment fragment, int i) {
        this.a = i;
        this.b = fragment;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        Fragment fragment = this.b;
        switch (this.a) {
            case 0:
                String str = NewSearchFragment.o;
                NewSearchFragment newSearchFragment = (NewSearchFragment) fragment;
                newSearchFragment.getClass();
                Context contextRequireContext = newSearchFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                ComposeView composeView = new ComposeView(contextRequireContext, null, 6);
                composeView.setContent(new androidx.compose.runtime.internal.d(true, 289957117, new c(newSearchFragment, 1)));
                return composeView;
            case 1:
                String str2 = TermSearchFragment.V;
                TermSearchFragment termSearchFragment = (TermSearchFragment) fragment;
                termSearchFragment.getClass();
                Context contextRequireContext2 = termSearchFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                ComposeView composeView2 = new ComposeView(contextRequireContext2, null, 6);
                composeView2.setContent(new androidx.compose.runtime.internal.d(true, 1610623407, new h(termSearchFragment, 1)));
                return composeView2;
            case 2:
                PaywallFragment paywallFragment = (PaywallFragment) fragment;
                paywallFragment.getClass();
                Context contextRequireContext3 = paywallFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext3, "requireContext(...)");
                ComposeView composeView3 = new ComposeView(contextRequireContext3, null, 6);
                composeView3.setContent(new androidx.compose.runtime.internal.d(true, 1486548490, new com.quizlet.upgrade.paywall.ui.a(paywallFragment, 1)));
                return composeView3;
            default:
                String str3 = UpgradeConfirmationFragment.l;
                UpgradeConfirmationFragment upgradeConfirmationFragment = (UpgradeConfirmationFragment) fragment;
                Context contextRequireContext4 = upgradeConfirmationFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext4, "requireContext(...)");
                ComposeView composeView4 = new ComposeView(contextRequireContext4, null, 6);
                composeView4.setContent(new androidx.compose.runtime.internal.d(true, -273354485, new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.c(upgradeConfirmationFragment, 8)));
                return composeView4;
        }
    }
}
