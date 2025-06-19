package com.google.android.material.transformation;

import android.content.Context;
import android.graphics.Rect;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.util.Pair;
import android.view.View;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.coordinatorlayout.widget.e;
import com.google.android.material.animation.f;
import com.google.android.material.animation.g;
import com.google.android.material.animation.h;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.skydoves.balloon.internals.DefinitionKt;

@Deprecated
/* loaded from: classes2.dex */
public abstract class FabTransformationBehavior extends ExpandableTransformationBehavior {
    public final Rect c;
    public final RectF d;
    public final RectF e;
    public final int[] f;
    public float g;
    public float h;

    public FabTransformationBehavior() {
        this.c = new Rect();
        this.d = new RectF();
        this.e = new RectF();
        this.f = new int[2];
    }

    public static float B(com.quizlet.data.repository.widget.b bVar, g gVar, float f) {
        long j = gVar.a;
        g gVarF = ((f) bVar.b).f("expansion");
        return com.google.android.material.animation.a.a(f, DefinitionKt.NO_Float_VALUE, gVar.b().getInterpolation((((gVarF.a + gVarF.b) + 17) - j) / gVar.b));
    }

    public static Pair y(float f, float f2, boolean z, com.quizlet.data.repository.widget.b bVar) {
        g gVarF;
        g gVarF2;
        if (f == DefinitionKt.NO_Float_VALUE || f2 == DefinitionKt.NO_Float_VALUE) {
            gVarF = ((f) bVar.b).f("translationXLinear");
            gVarF2 = ((f) bVar.b).f("translationYLinear");
        } else if ((!z || f2 >= DefinitionKt.NO_Float_VALUE) && (z || f2 <= DefinitionKt.NO_Float_VALUE)) {
            gVarF = ((f) bVar.b).f("translationXCurveDownwards");
            gVarF2 = ((f) bVar.b).f("translationYCurveDownwards");
        } else {
            gVarF = ((f) bVar.b).f("translationXCurveUpwards");
            gVarF2 = ((f) bVar.b).f("translationYCurveUpwards");
        }
        return new Pair(gVarF, gVarF2);
    }

    public final float A(View view, View view2, h hVar) {
        RectF rectF = this.d;
        RectF rectF2 = this.e;
        C(view, rectF);
        rectF.offset(this.g, this.h);
        C(view2, rectF2);
        hVar.getClass();
        return (rectF2.centerY() - rectF.centerY()) + DefinitionKt.NO_Float_VALUE;
    }

    public final void C(View view, RectF rectF) {
        rectF.set(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, view.getWidth(), view.getHeight());
        view.getLocationInWindow(this.f);
        rectF.offsetTo(r0[0], r0[1]);
        rectF.offset((int) (-view.getTranslationX()), (int) (-view.getTranslationY()));
    }

    public abstract com.quizlet.data.repository.widget.b D(Context context, boolean z);

    @Override // com.google.android.material.transformation.ExpandableBehavior, androidx.coordinatorlayout.widget.b
    public final boolean f(CoordinatorLayout coordinatorLayout, View view, View view2) {
        if (view.getVisibility() == 8) {
            throw new IllegalStateException("This behavior cannot be attached to a GONE view. Set the view to INVISIBLE instead.");
        }
        if (!(view2 instanceof FloatingActionButton)) {
            return false;
        }
        int expandedComponentIdHint = ((FloatingActionButton) view2).getExpandedComponentIdHint();
        return expandedComponentIdHint == 0 || expandedComponentIdHint == view.getId();
    }

    @Override // androidx.coordinatorlayout.widget.b
    public final void g(e eVar) {
        if (eVar.h == 0) {
            eVar.h = 80;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0152  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x035f  */
    @Override // com.google.android.material.transformation.ExpandableTransformationBehavior
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.animation.AnimatorSet x(android.view.View r25, android.view.View r26, boolean r27, boolean r28) {
        /*
            Method dump skipped, instructions count: 971
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.transformation.FabTransformationBehavior.x(android.view.View, android.view.View, boolean, boolean):android.animation.AnimatorSet");
    }

    public final float z(View view, View view2, h hVar) {
        RectF rectF = this.d;
        RectF rectF2 = this.e;
        C(view, rectF);
        rectF.offset(this.g, this.h);
        C(view2, rectF2);
        hVar.getClass();
        return (rectF2.centerX() - rectF.centerX()) + DefinitionKt.NO_Float_VALUE;
    }

    public FabTransformationBehavior(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.c = new Rect();
        this.d = new RectF();
        this.e = new RectF();
        this.f = new int[2];
    }
}
