package com.quizlet.upgrade.ui.fragment;

import android.view.View;
import com.quizlet.upgrade.data.o;
import kotlin.Unit;

/* loaded from: classes3.dex */
public final /* synthetic */ class d implements View.OnClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ UpgradeFragment b;

    public /* synthetic */ d(UpgradeFragment upgradeFragment, int i) {
        this.a = i;
        this.b = upgradeFragment;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        UpgradeFragment upgradeFragment = this.b;
        switch (this.a) {
            case 0:
                String str = UpgradeFragment.r;
                upgradeFragment.T().m.j(Unit.a);
                break;
            default:
                String str2 = UpgradeFragment.r;
                com.quizlet.upgrade.viewmodel.n nVarU = upgradeFragment.U();
                nVarU.getClass();
                nVarU.f.j(new o(null));
                break;
        }
    }
}
