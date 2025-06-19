package com.google.android.material.bottomsheet;

import android.content.res.Resources;
import android.view.View;
import com.quizlet.quizletandroid.databinding.C4610n;
import com.quizlet.quizletandroid.ui.common.dialogs.BaseConvertableModalDialogFragment;
import com.quizlet.quizletandroid.ui.diagramming.DiagramOverviewActivity;
import com.quizlet.uicommon.ui.common.dialogs.FullScreenConvertibleModalDialogFragment;
import com.quizlet.uicommon.ui.common.dialogs.UnstyledConvertibleModalDialogFragment;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class f extends c {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ f(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    private final void d(View view, float f) {
    }

    @Override // com.google.android.material.bottomsheet.c
    public final void b(View bottomSheet, float f) {
        switch (this.a) {
            case 0:
                break;
            case 1:
                Intrinsics.checkNotNullParameter(bottomSheet, "bottomSheet");
                break;
            case 2:
                Intrinsics.checkNotNullParameter(bottomSheet, "p0");
                int i = DiagramOverviewActivity.o1;
                ((DiagramOverviewActivity) this.b).d0().setAlpha(1 + f);
                break;
            case 3:
                Intrinsics.checkNotNullParameter(bottomSheet, "bottomSheet");
                break;
            default:
                Intrinsics.checkNotNullParameter(bottomSheet, "bottomSheet");
                break;
        }
    }

    @Override // com.google.android.material.bottomsheet.c
    public final void c(int i, View bottomSheet) {
        Object obj = this.b;
        switch (this.a) {
            case 0:
                if (i == 5) {
                    ((h) obj).cancel();
                    break;
                }
                break;
            case 1:
                Intrinsics.checkNotNullParameter(bottomSheet, "bottomSheet");
                BaseConvertableModalDialogFragment baseConvertableModalDialogFragment = (BaseConvertableModalDialogFragment) obj;
                switch (i) {
                    case 1:
                        ((C4610n) baseConvertableModalDialogFragment.P()).b.setVisibility(4);
                        ((C4610n) baseConvertableModalDialogFragment.P()).e.setVisibility(4);
                        ((C4610n) baseConvertableModalDialogFragment.P()).c.setVisibility(0);
                        break;
                    case 2:
                    case 4:
                    case 6:
                        ((C4610n) baseConvertableModalDialogFragment.P()).b.setVisibility(4);
                        break;
                    case 3:
                        if (bottomSheet.getHeight() == Resources.getSystem().getDisplayMetrics().heightPixels) {
                            ((C4610n) baseConvertableModalDialogFragment.P()).b.setVisibility(0);
                            ((C4610n) baseConvertableModalDialogFragment.P()).c.setVisibility(8);
                        }
                        ((C4610n) baseConvertableModalDialogFragment.P()).e.setVisibility(4);
                        break;
                    case 5:
                        baseConvertableModalDialogFragment.H(false, false);
                        break;
                }
            case 2:
                Intrinsics.checkNotNullParameter(bottomSheet, "view");
                DiagramOverviewActivity diagramOverviewActivity = (DiagramOverviewActivity) obj;
                if (i == 3) {
                    int i2 = DiagramOverviewActivity.o1;
                    diagramOverviewActivity.d0().setAlpha(1.0f);
                    diagramOverviewActivity.d0().setClickable(true);
                    break;
                } else if (i == 5) {
                    int i3 = DiagramOverviewActivity.o1;
                    diagramOverviewActivity.d0().setAlpha(DefinitionKt.NO_Float_VALUE);
                    diagramOverviewActivity.d0().setClickable(false);
                    break;
                }
                break;
            case 3:
                Intrinsics.checkNotNullParameter(bottomSheet, "bottomSheet");
                if (i == 4 || i == 5) {
                    ((FullScreenConvertibleModalDialogFragment) obj).H(true, false);
                    break;
                }
            default:
                Intrinsics.checkNotNullParameter(bottomSheet, "bottomSheet");
                if (i == 5) {
                    ((UnstyledConvertibleModalDialogFragment) obj).J();
                    break;
                }
                break;
        }
    }
}
