package com.quizlet.upgrade.ui.activity;

import android.content.Context;
import android.view.View;
import com.quizlet.quizletandroid.R;
import com.quizlet.upgrade.data.o;
import com.quizlet.upgrade.ui.fragment.TermsAndConditionsModalFragment;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class c implements View.OnClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ c(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        Object obj = this.b;
        switch (this.a) {
            case 0:
                String str = UpgradeActivity.v;
                ((UpgradeActivity) obj).b0(new o(null));
                return;
            default:
                TermsAndConditionsModalFragment termsAndConditionsModalFragment = (TermsAndConditionsModalFragment) obj;
                if (termsAndConditionsModalFragment.I == null) {
                    Intrinsics.m("upgradeNavigationManager");
                    throw null;
                }
                Context context = termsAndConditionsModalFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(context, "requireContext(...)");
                Intrinsics.checkNotNullParameter(context, "context");
                com.quizlet.quizletandroid.ui.webpages.a.a.b(context, "https://quizlet.com/tos", context.getString(R.string.user_settings_terms_of_service));
                return;
        }
    }
}
