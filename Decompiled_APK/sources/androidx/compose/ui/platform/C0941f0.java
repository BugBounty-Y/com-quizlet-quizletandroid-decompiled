package androidx.compose.ui.platform;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import java.util.HashMap;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.compose.ui.platform.f0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0941f0 extends ViewGroup {
    public final HashMap a;
    public final HashMap b;

    public C0941f0(@NotNull Context context) {
        super(context);
        setClipChildren(false);
        this.a = new HashMap();
        this.b = new HashMap();
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void dispatchDraw(Canvas canvas) {
    }

    @Override // android.view.ViewGroup, android.view.View
    public final boolean dispatchTouchEvent(MotionEvent motionEvent) {
        return true;
    }

    @NotNull
    public final HashMap<androidx.compose.ui.viewinterop.i, androidx.compose.ui.node.E> getHolderToLayoutNode() {
        return this.a;
    }

    @NotNull
    public final HashMap<androidx.compose.ui.node.E, androidx.compose.ui.viewinterop.i> getLayoutNodeToHolder() {
        return this.b;
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final /* bridge */ /* synthetic */ ViewParent invalidateChildInParent(int[] iArr, Rect rect) {
        return null;
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final void onDescendantInvalidated(View view, View view2) {
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onLayout(boolean z, int i, int i2, int i3, int i4) {
        for (androidx.compose.ui.viewinterop.i iVar : this.a.keySet()) {
            iVar.layout(iVar.getLeft(), iVar.getTop(), iVar.getRight(), iVar.getBottom());
        }
    }

    @Override // android.view.View
    public final void onMeasure(int i, int i2) {
        int i3;
        if (!(View.MeasureSpec.getMode(i) == 1073741824)) {
            W4.e("widthMeasureSpec should be EXACTLY");
            throw null;
        }
        if (!(View.MeasureSpec.getMode(i2) == 1073741824)) {
            W4.e("heightMeasureSpec should be EXACTLY");
            throw null;
        }
        setMeasuredDimension(View.MeasureSpec.getSize(i), View.MeasureSpec.getSize(i2));
        for (androidx.compose.ui.viewinterop.i iVar : this.a.keySet()) {
            int i4 = iVar.r;
            if (i4 != Integer.MIN_VALUE && (i3 = iVar.s) != Integer.MIN_VALUE) {
                iVar.measure(i4, i3);
            }
        }
    }

    @Override // android.view.View, android.view.ViewParent
    public final void requestLayout() {
        cleanupLayoutState(this);
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            View childAt = getChildAt(i);
            androidx.compose.ui.node.E e = (androidx.compose.ui.node.E) this.a.get(childAt);
            if (childAt.isLayoutRequested() && e != null) {
                androidx.compose.ui.node.E.T(e, false, 7);
            }
        }
    }

    @Override // android.view.ViewGroup
    public final boolean shouldDelayChildPressedState() {
        return false;
    }
}
