package androidx.transition;

import android.animation.Animator;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.graphics.PointF;
import android.graphics.Rect;
import android.view.View;
import android.view.ViewGroup;
import androidx.appcompat.widget.k1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3367m2;
import java.util.HashMap;

/* renamed from: androidx.transition.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1402e extends y {
    public static final String[] F = {"android:changeBounds:bounds", "android:changeBounds:clip", "android:changeBounds:parent", "android:changeBounds:windowX", "android:changeBounds:windowY"};
    public static final k1 G = new k1(1, PointF.class, "topLeft");
    public static final k1 H = new k1(2, PointF.class, "bottomRight");
    public static final k1 I = new k1(3, PointF.class, "bottomRight");
    public static final k1 J = new k1(4, PointF.class, "topLeft");
    public static final k1 K = new k1(5, PointF.class, "position");

    public static void R(I i) {
        View view = i.b;
        if (!view.isLaidOut() && view.getWidth() == 0 && view.getHeight() == 0) {
            return;
        }
        HashMap map = i.a;
        map.put("android:changeBounds:bounds", new Rect(view.getLeft(), view.getTop(), view.getRight(), view.getBottom()));
        map.put("android:changeBounds:parent", i.b.getParent());
    }

    @Override // androidx.transition.y
    public final void e(I i) {
        R(i);
    }

    @Override // androidx.transition.y
    public final void h(I i) {
        R(i);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // androidx.transition.y
    public final Animator m(ViewGroup viewGroup, I i, I i2) {
        int i3;
        C1402e c1402e;
        ObjectAnimator objectAnimatorA;
        if (i != null && i2 != null) {
            HashMap map = i.a;
            HashMap map2 = i2.a;
            ViewGroup viewGroup2 = (ViewGroup) map.get("android:changeBounds:parent");
            ViewGroup viewGroup3 = (ViewGroup) map2.get("android:changeBounds:parent");
            if (viewGroup2 != null && viewGroup3 != null) {
                Rect rect = (Rect) map.get("android:changeBounds:bounds");
                Rect rect2 = (Rect) map2.get("android:changeBounds:bounds");
                int i4 = rect.left;
                int i5 = rect2.left;
                int i6 = rect.top;
                int i7 = rect2.top;
                int i8 = rect.right;
                int i9 = rect2.right;
                int i10 = rect.bottom;
                int i11 = rect2.bottom;
                int i12 = i8 - i4;
                int i13 = i10 - i6;
                int i14 = i9 - i5;
                int i15 = i11 - i7;
                Rect rect3 = (Rect) map.get("android:changeBounds:clip");
                Rect rect4 = (Rect) map2.get("android:changeBounds:clip");
                if ((i12 == 0 || i13 == 0) && (i14 == 0 || i15 == 0)) {
                    i3 = 0;
                } else {
                    i3 = (i4 == i5 && i6 == i7) ? 0 : 1;
                    if (i8 != i9 || i10 != i11) {
                        i3++;
                    }
                }
                if ((rect3 != null && !rect3.equals(rect4)) || (rect3 == null && rect4 != null)) {
                    i3++;
                }
                if (i3 > 0) {
                    View view = i2.b;
                    L.a(view, i4, i6, i8, i10);
                    if (i3 != 2) {
                        c1402e = this;
                        if (i4 == i5 && i6 == i7) {
                            c1402e.x.getClass();
                            objectAnimatorA = AbstractC1410m.a(view, I, C1411n.a(i8, i10, i9, i11));
                        } else {
                            c1402e.x.getClass();
                            objectAnimatorA = AbstractC1410m.a(view, J, C1411n.a(i4, i6, i5, i7));
                        }
                    } else if (i12 == i14 && i13 == i15) {
                        c1402e = this;
                        c1402e.x.getClass();
                        objectAnimatorA = AbstractC1410m.a(view, K, C1411n.a(i4, i6, i5, i7));
                    } else {
                        c1402e = this;
                        C1401d c1401d = new C1401d(view);
                        c1402e.x.getClass();
                        ObjectAnimator objectAnimatorA2 = AbstractC1410m.a(c1401d, G, C1411n.a(i4, i6, i5, i7));
                        c1402e.x.getClass();
                        ObjectAnimator objectAnimatorA3 = AbstractC1410m.a(c1401d, H, C1411n.a(i8, i10, i9, i11));
                        AnimatorSet animatorSet = new AnimatorSet();
                        animatorSet.playTogether(objectAnimatorA2, objectAnimatorA3);
                        animatorSet.addListener(new C1399b(c1401d));
                        objectAnimatorA = animatorSet;
                    }
                    if (view.getParent() instanceof ViewGroup) {
                        ViewGroup viewGroup4 = (ViewGroup) view.getParent();
                        AbstractC3367m2.b(viewGroup4, true);
                        c1402e.q().b(new C1400c(viewGroup4));
                    }
                    return objectAnimatorA;
                }
            }
        }
        return null;
    }

    @Override // androidx.transition.y
    public final String[] s() {
        return F;
    }

    @Override // androidx.transition.y
    public final boolean v() {
        return true;
    }
}
