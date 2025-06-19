package com.google.android.material.floatingactionbutton;

import android.animation.Animator;
import android.animation.AnimatorSet;
import android.animation.PropertyValuesHolder;
import android.text.TextUtils;
import android.view.ViewGroup;
import androidx.core.view.V;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.quizletandroid.R;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public final class d extends a {
    public final g g;
    public final boolean h;
    public final /* synthetic */ ExtendedFloatingActionButton i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(ExtendedFloatingActionButton extendedFloatingActionButton, com.airbnb.lottie.network.d dVar, g gVar, boolean z) {
        super(extendedFloatingActionButton, dVar);
        this.i = extendedFloatingActionButton;
        this.g = gVar;
        this.h = z;
    }

    @Override // com.google.android.material.floatingactionbutton.a
    public final AnimatorSet a() {
        com.google.android.material.animation.f fVar = this.f;
        if (fVar == null) {
            if (this.e == null) {
                this.e = com.google.android.material.animation.f.b(this.a, c());
            }
            fVar = this.e;
            fVar.getClass();
        }
        boolean zG = fVar.g(OTUXParamsKeys.OT_UX_WIDTH);
        g gVar = this.g;
        ExtendedFloatingActionButton extendedFloatingActionButton = this.i;
        if (zG) {
            PropertyValuesHolder[] propertyValuesHolderArrE = fVar.e(OTUXParamsKeys.OT_UX_WIDTH);
            propertyValuesHolderArrE[0].setFloatValues(extendedFloatingActionButton.getWidth(), gVar.getWidth());
            fVar.h(OTUXParamsKeys.OT_UX_WIDTH, propertyValuesHolderArrE);
        }
        if (fVar.g(OTUXParamsKeys.OT_UX_HEIGHT)) {
            PropertyValuesHolder[] propertyValuesHolderArrE2 = fVar.e(OTUXParamsKeys.OT_UX_HEIGHT);
            propertyValuesHolderArrE2[0].setFloatValues(extendedFloatingActionButton.getHeight(), gVar.b());
            fVar.h(OTUXParamsKeys.OT_UX_HEIGHT, propertyValuesHolderArrE2);
        }
        if (fVar.g("paddingStart")) {
            PropertyValuesHolder[] propertyValuesHolderArrE3 = fVar.e("paddingStart");
            PropertyValuesHolder propertyValuesHolder = propertyValuesHolderArrE3[0];
            WeakHashMap weakHashMap = V.a;
            propertyValuesHolder.setFloatValues(extendedFloatingActionButton.getPaddingStart(), gVar.v());
            fVar.h("paddingStart", propertyValuesHolderArrE3);
        }
        if (fVar.g("paddingEnd")) {
            PropertyValuesHolder[] propertyValuesHolderArrE4 = fVar.e("paddingEnd");
            PropertyValuesHolder propertyValuesHolder2 = propertyValuesHolderArrE4[0];
            WeakHashMap weakHashMap2 = V.a;
            propertyValuesHolder2.setFloatValues(extendedFloatingActionButton.getPaddingEnd(), gVar.i());
            fVar.h("paddingEnd", propertyValuesHolderArrE4);
        }
        if (fVar.g("labelOpacity")) {
            PropertyValuesHolder[] propertyValuesHolderArrE5 = fVar.e("labelOpacity");
            boolean z = this.h;
            propertyValuesHolderArrE5[0].setFloatValues(z ? 0.0f : 1.0f, z ? 1.0f : 0.0f);
            fVar.h("labelOpacity", propertyValuesHolderArrE5);
        }
        return b(fVar);
    }

    @Override // com.google.android.material.floatingactionbutton.a
    public final int c() {
        return this.h ? R.animator.mtrl_extended_fab_change_size_expand_motion_spec : R.animator.mtrl_extended_fab_change_size_collapse_motion_spec;
    }

    @Override // com.google.android.material.floatingactionbutton.a
    public final void e() {
        this.d.b = null;
        ExtendedFloatingActionButton extendedFloatingActionButton = this.i;
        extendedFloatingActionButton.D = false;
        extendedFloatingActionButton.setHorizontallyScrolling(false);
        ViewGroup.LayoutParams layoutParams = extendedFloatingActionButton.getLayoutParams();
        if (layoutParams == null) {
            return;
        }
        g gVar = this.g;
        layoutParams.width = gVar.getLayoutParams().width;
        layoutParams.height = gVar.getLayoutParams().height;
    }

    @Override // com.google.android.material.floatingactionbutton.a
    public final void f(Animator animator) {
        com.airbnb.lottie.network.d dVar = this.d;
        Animator animator2 = (Animator) dVar.b;
        if (animator2 != null) {
            animator2.cancel();
        }
        dVar.b = animator;
        boolean z = this.h;
        ExtendedFloatingActionButton extendedFloatingActionButton = this.i;
        extendedFloatingActionButton.C = z;
        extendedFloatingActionButton.D = true;
        extendedFloatingActionButton.setHorizontallyScrolling(true);
    }

    @Override // com.google.android.material.floatingactionbutton.a
    public final void g() {
        ExtendedFloatingActionButton extendedFloatingActionButton = this.i;
        boolean z = this.h;
        extendedFloatingActionButton.C = z;
        ViewGroup.LayoutParams layoutParams = extendedFloatingActionButton.getLayoutParams();
        if (layoutParams == null) {
            return;
        }
        if (!z) {
            extendedFloatingActionButton.G = layoutParams.width;
            extendedFloatingActionButton.H = layoutParams.height;
        }
        g gVar = this.g;
        layoutParams.width = gVar.getLayoutParams().width;
        layoutParams.height = gVar.getLayoutParams().height;
        int iV = gVar.v();
        int paddingTop = extendedFloatingActionButton.getPaddingTop();
        int i = gVar.i();
        int paddingBottom = extendedFloatingActionButton.getPaddingBottom();
        WeakHashMap weakHashMap = V.a;
        extendedFloatingActionButton.setPaddingRelative(iV, paddingTop, i, paddingBottom);
        extendedFloatingActionButton.requestLayout();
    }

    @Override // com.google.android.material.floatingactionbutton.a
    public final boolean h() {
        ExtendedFloatingActionButton extendedFloatingActionButton = this.i;
        return this.h == extendedFloatingActionButton.C || extendedFloatingActionButton.getIcon() == null || TextUtils.isEmpty(extendedFloatingActionButton.getText());
    }
}
