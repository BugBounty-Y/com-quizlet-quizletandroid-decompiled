package com.quizlet.upgrade.ui.activity;

import android.os.Bundle;
import android.view.View;
import androidx.appcompat.widget.Toolbar;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.core.view.D0;
import androidx.core.view.InterfaceC1062t;
import androidx.fragment.app.m0;
import com.quizlet.upgrade.data.UpgradePackage;
import com.quizlet.upgrade.data.o;
import com.quizlet.upgrade.ui.confirmation.UpgradeConfirmationFragment;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements m0, InterfaceC1062t {
    public final /* synthetic */ UpgradeActivity a;

    public /* synthetic */ a(UpgradeActivity upgradeActivity) {
        this.a = upgradeActivity;
    }

    @Override // androidx.core.view.InterfaceC1062t
    public D0 w(D0 d0, View view) {
        String str = UpgradeActivity.v;
        androidx.core.graphics.e eVarG = d0.a.g(647);
        UpgradeActivity upgradeActivity = this.a;
        Toolbar toolbar = ((com.quizlet.upgrade.databinding.a) upgradeActivity.K()).c;
        Intrinsics.checkNotNullExpressionValue(toolbar, "toolbar");
        toolbar.setPadding(toolbar.getPaddingLeft(), eVarG.b, toolbar.getPaddingRight(), toolbar.getPaddingBottom());
        ConstraintLayout constraintLayout = ((com.quizlet.upgrade.databinding.a) upgradeActivity.K()).a;
        Intrinsics.checkNotNullExpressionValue(constraintLayout, "getRoot(...)");
        constraintLayout.setPadding(constraintLayout.getPaddingLeft(), constraintLayout.getPaddingTop(), constraintLayout.getPaddingRight(), eVarG.d);
        return D0.b;
    }

    @Override // androidx.fragment.app.m0
    public void y(Bundle bundle, String str) {
        String str2 = UpgradeActivity.v;
        Intrinsics.checkNotNullParameter(str, "<unused var>");
        Intrinsics.checkNotNullParameter(bundle, "bundle");
        if (bundle.containsKey("ResultUserUpgradeType")) {
            int i = bundle.getInt("ResultUserUpgradeType", 0);
            UpgradeActivity upgradeActivity = this.a;
            if (i == 0) {
                upgradeActivity.b0(new o(Integer.valueOf(i)));
                return;
            }
            UpgradePackage upgradePackage = UpgradePackage.c;
            Intrinsics.checkNotNullParameter(upgradePackage, "defaultUpgradePackage");
            if (i != 0) {
                if (i == 1) {
                    upgradePackage = UpgradePackage.d;
                } else if (i != 2) {
                    throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Unknown user type "));
                }
            }
            String str3 = UpgradeConfirmationFragment.l;
            Intrinsics.checkNotNullParameter(upgradePackage, "upgradePackage");
            UpgradeConfirmationFragment upgradeConfirmationFragment = new UpgradeConfirmationFragment();
            Bundle bundle2 = new Bundle();
            bundle2.putParcelable("upgradePackage", upgradePackage);
            upgradeConfirmationFragment.setArguments(bundle2);
            upgradeActivity.c0(upgradeConfirmationFragment);
        }
    }
}
