package androidx.appcompat.widget;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.ValueAnimator;
import android.content.res.ColorStateList;
import android.view.View;
import com.google.android.material.behavior.HideBottomViewOnScrollBehavior;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.checkbox.MaterialCheckBox;
import com.google.android.material.sidesheet.SideSheetBehavior;
import com.google.android.material.transformation.ExpandableTransformationBehavior;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.appcompat.widget.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0076c extends AnimatorListenerAdapter {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ C0076c(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public void onAnimationCancel(Animator animator) {
        switch (this.a) {
            case 0:
                ActionBarOverlayLayout actionBarOverlayLayout = (ActionBarOverlayLayout) this.b;
                actionBarOverlayLayout.w = null;
                actionBarOverlayLayout.j = false;
                break;
            case 3:
                com.google.android.gms.ads.internal.overlay.l lVar = (com.google.android.gms.ads.internal.overlay.l) this.b;
                lVar.setEnabled(true);
                lVar.a.setEnabled(true);
                break;
            case 6:
                ((com.google.android.material.floatingactionbutton.a) this.b).d();
                break;
            default:
                super.onAnimationCancel(animator);
                break;
        }
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public final void onAnimationEnd(Animator animation) {
        switch (this.a) {
            case 0:
                ActionBarOverlayLayout actionBarOverlayLayout = (ActionBarOverlayLayout) this.b;
                actionBarOverlayLayout.w = null;
                actionBarOverlayLayout.j = false;
                break;
            case 1:
                ((androidx.transition.y) this.b).o();
                animation.removeListener(this);
                break;
            case 2:
                androidx.vectordrawable.graphics.drawable.f fVar = (androidx.vectordrawable.graphics.drawable.f) this.b;
                ArrayList arrayList = new ArrayList(fVar.e);
                int size = arrayList.size();
                for (int i = 0; i < size; i++) {
                    ColorStateList colorStateList = ((com.google.android.material.checkbox.a) arrayList.get(i)).b.o;
                    if (colorStateList != null) {
                        fVar.setTintList(colorStateList);
                    }
                }
                break;
            case 3:
                com.google.android.gms.ads.internal.overlay.l lVar = (com.google.android.gms.ads.internal.overlay.l) this.b;
                lVar.setEnabled(true);
                lVar.a.setEnabled(true);
                break;
            case 4:
                ((HideBottomViewOnScrollBehavior) this.b).i = null;
                break;
            case 5:
                BottomSheetBehavior bottomSheetBehavior = (BottomSheetBehavior) this.b;
                bottomSheetBehavior.K(5);
                WeakReference weakReference = bottomSheetBehavior.e1;
                if (weakReference != null && weakReference.get() != null) {
                    ((View) bottomSheetBehavior.e1.get()).requestLayout();
                    break;
                }
                break;
            case 6:
                ((com.google.android.material.floatingactionbutton.a) this.b).e();
                break;
            case 7:
                com.quizlet.data.repository.folderset.c cVar = (com.quizlet.data.repository.folderset.c) this.b;
                if (((ValueAnimator) cVar.c) == animation) {
                    cVar.c = null;
                    break;
                }
                break;
            case 8:
                com.google.android.material.motion.f fVar2 = (com.google.android.material.motion.f) this.b;
                fVar2.b.setTranslationY(DefinitionKt.NO_Float_VALUE);
                fVar2.c(DefinitionKt.NO_Float_VALUE);
                break;
            case 9:
                View view = (View) this.b;
                if (view != null) {
                    view.setVisibility(0);
                    break;
                }
                break;
            case 10:
                SideSheetBehavior sideSheetBehavior = (SideSheetBehavior) this.b;
                sideSheetBehavior.x(5);
                WeakReference weakReference2 = sideSheetBehavior.p;
                if (weakReference2 != null && weakReference2.get() != null) {
                    ((View) sideSheetBehavior.p.get()).requestLayout();
                    break;
                }
                break;
            case 11:
                com.google.android.material.textfield.i iVar = (com.google.android.material.textfield.i) this.b;
                iVar.q();
                iVar.r.start();
                break;
            case 12:
                ((ExpandableTransformationBehavior) this.b).b = null;
                break;
            default:
                Intrinsics.checkNotNullParameter(animation, "animation");
                ((com.quizlet.quizletandroid.ui.setcreation.viewholders.g) this.b).e.setVisibility(8);
                break;
        }
    }

    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
    public void onAnimationStart(Animator animation) {
        switch (this.a) {
            case 2:
                androidx.vectordrawable.graphics.drawable.f fVar = (androidx.vectordrawable.graphics.drawable.f) this.b;
                ArrayList arrayList = new ArrayList(fVar.e);
                int size = arrayList.size();
                for (int i = 0; i < size; i++) {
                    MaterialCheckBox materialCheckBox = ((com.google.android.material.checkbox.a) arrayList.get(i)).b;
                    ColorStateList colorStateList = materialCheckBox.o;
                    if (colorStateList != null) {
                        fVar.setTint(colorStateList.getColorForState(materialCheckBox.s, colorStateList.getDefaultColor()));
                    }
                }
                break;
            case 3:
                com.google.android.gms.ads.internal.overlay.l lVar = (com.google.android.gms.ads.internal.overlay.l) this.b;
                lVar.setEnabled(false);
                lVar.a.setEnabled(false);
                break;
            case 6:
                ((com.google.android.material.floatingactionbutton.a) this.b).f(animation);
                break;
            case 13:
                Intrinsics.checkNotNullParameter(animation, "animation");
                break;
            default:
                super.onAnimationStart(animation);
                break;
        }
    }
}
