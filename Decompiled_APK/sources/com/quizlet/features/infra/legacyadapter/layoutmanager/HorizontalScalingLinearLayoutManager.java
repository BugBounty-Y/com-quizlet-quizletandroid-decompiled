package com.quizlet.features.infra.legacyadapter.layoutmanager;

import android.view.View;
import androidx.recyclerview.widget.AbstractC1381n0;
import androidx.recyclerview.widget.B0;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.v0;
import com.quizlet.quizletandroid.ui.preview.SetPreviewActivity;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class HorizontalScalingLinearLayoutManager extends LinearLayoutManager {
    public final float E;
    public final float F;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public HorizontalScalingLinearLayoutManager(SetPreviewActivity context) {
        super(0);
        Intrinsics.checkNotNullParameter(context, "context");
        this.E = 0.93f;
        this.F = 0.7f;
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    public final void h0(v0 recycler, B0 state) {
        Intrinsics.checkNotNullParameter(recycler, "recycler");
        Intrinsics.checkNotNullParameter(state, "state");
        super.h0(recycler, state);
        u0(0, recycler, state);
    }

    @Override // androidx.recyclerview.widget.LinearLayoutManager, androidx.recyclerview.widget.AbstractC1381n0
    public final int u0(int i, v0 v0Var, B0 b0) {
        int iU0 = super.u0(i, v0Var, b0);
        float f = this.n / 2.0f;
        if (f > DefinitionKt.NO_Float_VALUE) {
            float f2 = 0.5f * f;
            int iV = v();
            for (int i2 = 0; i2 < iV; i2++) {
                View viewU = u(i2);
                if (viewU != null) {
                    float fAbs = Math.abs(f - ((AbstractC1381n0.A(viewU) + AbstractC1381n0.D(viewU)) / 2.0f));
                    if (f2 <= fAbs) {
                        fAbs = f2;
                    }
                    float f3 = this.E - 1.0f;
                    float f4 = fAbs - DefinitionKt.NO_Float_VALUE;
                    float f5 = f2 - DefinitionKt.NO_Float_VALUE;
                    float f6 = (((this.F - 1.0f) * f4) / f5) + 1.0f;
                    viewU.setScaleY(((f3 * f4) / f5) + 1.0f);
                    viewU.setAlpha(f6);
                }
            }
        }
        return iU0;
    }
}
