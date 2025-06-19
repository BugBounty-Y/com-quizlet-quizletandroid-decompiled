package com.quizlet.quizletandroid.ui.studymodes.testmode.activities;

import android.view.View;
import android.widget.FrameLayout;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.core.view.D0;
import androidx.core.view.InterfaceC1062t;
import com.quizlet.quizletandroid.databinding.C4606j;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements com.quizlet.uicommon.ui.common.dialogs.f, InterfaceC1062t {
    public final /* synthetic */ TestStudyModeActivity a;

    public /* synthetic */ b(TestStudyModeActivity testStudyModeActivity) {
        this.a = testStudyModeActivity;
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.f
    public void c(com.quizlet.uicommon.ui.common.dialogs.e eVar, int i) {
        String str = TestStudyModeActivity.v;
        eVar.dismiss();
        this.a.finish();
    }

    @Override // androidx.core.view.InterfaceC1062t
    public D0 w(D0 d0, View view) {
        String str = TestStudyModeActivity.v;
        androidx.core.graphics.e eVarG = d0.a.g(647);
        TestStudyModeActivity testStudyModeActivity = this.a;
        ConstraintLayout testToolbar = ((C4606j) testStudyModeActivity.K()).g;
        Intrinsics.checkNotNullExpressionValue(testToolbar, "testToolbar");
        int i = eVarG.b;
        int paddingBottom = testToolbar.getPaddingBottom();
        int i2 = eVarG.a;
        int i3 = eVarG.c;
        testToolbar.setPadding(i2, i, i3, paddingBottom);
        FrameLayout fragmentContainer = ((C4606j) testStudyModeActivity.K()).c;
        Intrinsics.checkNotNullExpressionValue(fragmentContainer, "fragmentContainer");
        fragmentContainer.setPadding(i2, eVarG.b, i3, eVarG.d);
        return D0.b;
    }
}
