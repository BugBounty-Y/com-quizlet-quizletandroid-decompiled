package com.google.android.material.chip;

import android.graphics.Outline;
import android.view.View;
import android.view.ViewOutlineProvider;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class c extends ViewOutlineProvider {
    public final /* synthetic */ Chip a;

    public c(Chip chip) {
        this.a = chip;
    }

    @Override // android.view.ViewOutlineProvider
    public final void getOutline(View view, Outline outline) {
        f fVar = this.a.e;
        if (fVar != null) {
            fVar.getOutline(outline);
        } else {
            outline.setAlpha(DefinitionKt.NO_Float_VALUE);
        }
    }
}
