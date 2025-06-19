package com.quizlet.upgrade.ui.fragment;

import android.content.Context;
import android.view.View;
import androidx.lifecycle.p0;
import com.quizlet.upgrade.data.B;
import com.quizlet.upgrade.data.z;
import com.skydoves.balloon.Balloon;
import com.skydoves.balloon.OnBalloonClickListener;
import com.skydoves.balloon.OnBalloonOverlayClickListener;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final /* synthetic */ class e implements View.OnClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ e(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        Object obj = this.b;
        Object obj2 = this.c;
        switch (this.a) {
            case 0:
                String str = UpgradeFragment.r;
                com.quizlet.upgrade.viewmodel.n nVarU = ((UpgradeFragment) obj).U();
                com.quizlet.data.model.billing.a subscriptionDetails = ((z) ((B) obj2)).a;
                nVarU.getClass();
                Intrinsics.checkNotNullParameter(subscriptionDetails, "subscriptionDetails");
                E.A(p0.j(nVarU), null, null, new com.quizlet.upgrade.viewmodel.l(nVarU, subscriptionDetails, null), 3);
                return;
            case 1:
                UpgradeFragment upgradeFragment = (UpgradeFragment) obj;
                com.quizlet.quizletandroid.ui.webpages.a aVar = upgradeFragment.l;
                if (aVar == null) {
                    Intrinsics.m("webPageHelper");
                    throw null;
                }
                Context contextRequireContext = upgradeFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                aVar.b(contextRequireContext, (String) obj2, null);
                return;
            case 2:
                String str2 = UpgradePlansModalFragment.W;
                com.quizlet.upgrade.viewmodel.n nVar = (com.quizlet.upgrade.viewmodel.n) ((UpgradePlansModalFragment) obj).J.getValue();
                com.quizlet.data.model.billing.a subscriptionDetails2 = ((com.quizlet.upgrade.data.m) obj2).b();
                nVar.getClass();
                Intrinsics.checkNotNullParameter(subscriptionDetails2, "subscriptionDetails");
                E.A(p0.j(nVar), null, null, new com.quizlet.upgrade.viewmodel.l(nVar, subscriptionDetails2, null), 3);
                return;
            case 3:
                Balloon.setOnBalloonClickListener$lambda$47((OnBalloonClickListener) obj, (Balloon) obj2, view);
                return;
            default:
                Balloon.setOnBalloonOverlayClickListener$lambda$51((OnBalloonOverlayClickListener) obj, (Balloon) obj2, view);
                return;
        }
    }
}
