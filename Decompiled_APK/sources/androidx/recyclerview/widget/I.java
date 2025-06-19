package androidx.recyclerview.widget;

import android.annotation.SuppressLint;
import android.graphics.Canvas;
import android.view.View;
import android.view.animation.Interpolator;
import androidx.annotation.NonNull;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public abstract class I {
    private static final Interpolator sDragScrollInterpolator = new H(0);
    private static final Interpolator sDragViewScrollCapInterpolator = new H(1);
    private int mCachedMaxScrollSpeed = -1;

    public static int convertToRelativeDirection(int i, int i2) {
        int i3;
        int i4 = i & 789516;
        if (i4 == 0) {
            return i;
        }
        int i5 = i & (~i4);
        if (i2 == 0) {
            i3 = i4 << 2;
        } else {
            int i6 = i4 << 1;
            i5 |= (-789517) & i6;
            i3 = (i6 & 789516) << 2;
        }
        return i5 | i3;
    }

    public static int makeFlag(int i, int i2) {
        return i2 << (i * 8);
    }

    public static int makeMovementFlags(int i, int i2) {
        return makeFlag(2, i) | makeFlag(1, i2) | makeFlag(0, i2 | i);
    }

    public boolean canDropOver(@NonNull RecyclerView recyclerView, @NonNull F0 f0, @NonNull F0 f02) {
        return true;
    }

    @SuppressLint({"UnknownNullness"})
    public F0 chooseDropTarget(@NonNull F0 f0, @NonNull List<F0> list, int i, int i2) {
        int bottom;
        int iAbs;
        int top;
        int iAbs2;
        int left;
        int iAbs3;
        int right;
        int iAbs4;
        int width = f0.itemView.getWidth() + i;
        int height = f0.itemView.getHeight() + i2;
        int left2 = i - f0.itemView.getLeft();
        int top2 = i2 - f0.itemView.getTop();
        int size = list.size();
        F0 f02 = null;
        int i3 = -1;
        for (int i4 = 0; i4 < size; i4++) {
            F0 f03 = list.get(i4);
            if (left2 > 0 && (right = f03.itemView.getRight() - width) < 0 && f03.itemView.getRight() > f0.itemView.getRight() && (iAbs4 = Math.abs(right)) > i3) {
                f02 = f03;
                i3 = iAbs4;
            }
            if (left2 < 0 && (left = f03.itemView.getLeft() - i) > 0 && f03.itemView.getLeft() < f0.itemView.getLeft() && (iAbs3 = Math.abs(left)) > i3) {
                f02 = f03;
                i3 = iAbs3;
            }
            if (top2 < 0 && (top = f03.itemView.getTop() - i2) > 0 && f03.itemView.getTop() < f0.itemView.getTop() && (iAbs2 = Math.abs(top)) > i3) {
                f02 = f03;
                i3 = iAbs2;
            }
            if (top2 > 0 && (bottom = f03.itemView.getBottom() - height) < 0 && f03.itemView.getBottom() > f0.itemView.getBottom() && (iAbs = Math.abs(bottom)) > i3) {
                f02 = f03;
                i3 = iAbs;
            }
        }
        return f02;
    }

    public void clearView(@NonNull RecyclerView recyclerView, @NonNull F0 f0) {
        View view = f0.itemView;
        Object tag = view.getTag(R.id.item_touch_helper_previous_elevation);
        if (tag instanceof Float) {
            float fFloatValue = ((Float) tag).floatValue();
            WeakHashMap weakHashMap = androidx.core.view.V.a;
            androidx.core.view.L.k(view, fFloatValue);
        }
        view.setTag(R.id.item_touch_helper_previous_elevation, null);
        view.setTranslationX(DefinitionKt.NO_Float_VALUE);
        view.setTranslationY(DefinitionKt.NO_Float_VALUE);
    }

    public int convertToAbsoluteDirection(int i, int i2) {
        int i3;
        int i4 = i & 3158064;
        if (i4 == 0) {
            return i;
        }
        int i5 = i & (~i4);
        if (i2 == 0) {
            i3 = i4 >> 2;
        } else {
            int i6 = i4 >> 1;
            i5 |= (-3158065) & i6;
            i3 = (i6 & 3158064) >> 2;
        }
        return i5 | i3;
    }

    public final int getAbsoluteMovementFlags(RecyclerView recyclerView, F0 f0) {
        return convertToAbsoluteDirection(getMovementFlags(recyclerView, f0), recyclerView.getLayoutDirection());
    }

    public long getAnimationDuration(@NonNull RecyclerView recyclerView, int i, float f, float f2) {
        AbstractC1373j0 itemAnimator = recyclerView.getItemAnimator();
        return itemAnimator == null ? i == 8 ? 200L : 250L : i == 8 ? itemAnimator.e : itemAnimator.d;
    }

    public int getBoundingBoxMargin() {
        return 0;
    }

    public float getMoveThreshold(@NonNull F0 f0) {
        return 0.5f;
    }

    public abstract int getMovementFlags(RecyclerView recyclerView, F0 f0);

    public float getSwipeEscapeVelocity(float f) {
        return f;
    }

    public float getSwipeThreshold(@NonNull F0 f0) {
        return 0.5f;
    }

    public float getSwipeVelocityThreshold(float f) {
        return f;
    }

    public boolean hasDragFlag(RecyclerView recyclerView, F0 f0) {
        return (getAbsoluteMovementFlags(recyclerView, f0) & 16711680) != 0;
    }

    public int interpolateOutOfBoundsScroll(@NonNull RecyclerView recyclerView, int i, int i2, int i3, long j) {
        if (this.mCachedMaxScrollSpeed == -1) {
            this.mCachedMaxScrollSpeed = recyclerView.getResources().getDimensionPixelSize(R.dimen.item_touch_helper_max_drag_scroll_per_frame);
        }
        int interpolation = (int) (sDragScrollInterpolator.getInterpolation(j <= 2000 ? j / 2000.0f : 1.0f) * ((int) (sDragViewScrollCapInterpolator.getInterpolation(Math.min(1.0f, (Math.abs(i2) * 1.0f) / i)) * ((int) Math.signum(i2)) * this.mCachedMaxScrollSpeed)));
        return interpolation == 0 ? i2 > 0 ? 1 : -1 : interpolation;
    }

    public abstract boolean isItemViewSwipeEnabled();

    public abstract boolean isLongPressDragEnabled();

    public void onChildDraw(@NonNull Canvas canvas, @NonNull RecyclerView recyclerView, @NonNull F0 f0, float f, float f2, int i, boolean z) {
        View view = f0.itemView;
        if (z && view.getTag(R.id.item_touch_helper_previous_elevation) == null) {
            WeakHashMap weakHashMap = androidx.core.view.V.a;
            Float fValueOf = Float.valueOf(androidx.core.view.L.e(view));
            int childCount = recyclerView.getChildCount();
            float f3 = DefinitionKt.NO_Float_VALUE;
            for (int i2 = 0; i2 < childCount; i2++) {
                View childAt = recyclerView.getChildAt(i2);
                if (childAt != view) {
                    WeakHashMap weakHashMap2 = androidx.core.view.V.a;
                    float fE = androidx.core.view.L.e(childAt);
                    if (fE > f3) {
                        f3 = fE;
                    }
                }
            }
            androidx.core.view.L.k(view, f3 + 1.0f);
            view.setTag(R.id.item_touch_helper_previous_elevation, fValueOf);
        }
        view.setTranslationX(f);
        view.setTranslationY(f2);
    }

    public void onChildDrawOver(@NonNull Canvas canvas, @NonNull RecyclerView recyclerView, @SuppressLint({"UnknownNullness"}) F0 f0, float f, float f2, int i, boolean z) {
        View view = f0.itemView;
    }

    public void onDraw(Canvas canvas, RecyclerView recyclerView, F0 f0, List<G> list, int i, float f, float f2) {
        int size = list.size();
        for (int i2 = 0; i2 < size; i2++) {
            G g = list.get(i2);
            float f3 = g.a;
            float f4 = g.c;
            F0 f02 = g.e;
            if (f3 == f4) {
                g.i = f02.itemView.getTranslationX();
            } else {
                g.i = android.support.v4.media.session.a.a(f4, f3, g.m, f3);
            }
            float f5 = g.b;
            float f6 = g.d;
            if (f5 == f6) {
                g.j = f02.itemView.getTranslationY();
            } else {
                g.j = android.support.v4.media.session.a.a(f6, f5, g.m, f5);
            }
            int iSave = canvas.save();
            onChildDraw(canvas, recyclerView, g.e, g.i, g.j, g.f, false);
            canvas.restoreToCount(iSave);
        }
        if (f0 != null) {
            int iSave2 = canvas.save();
            onChildDraw(canvas, recyclerView, f0, f, f2, i, true);
            canvas.restoreToCount(iSave2);
        }
    }

    public void onDrawOver(Canvas canvas, RecyclerView recyclerView, F0 f0, List<G> list, int i, float f, float f2) {
        int size = list.size();
        boolean z = false;
        for (int i2 = 0; i2 < size; i2++) {
            G g = list.get(i2);
            int iSave = canvas.save();
            onChildDrawOver(canvas, recyclerView, g.e, g.i, g.j, g.f, false);
            canvas.restoreToCount(iSave);
        }
        if (f0 != null) {
            int iSave2 = canvas.save();
            onChildDrawOver(canvas, recyclerView, f0, f, f2, i, true);
            canvas.restoreToCount(iSave2);
        }
        for (int i3 = size - 1; i3 >= 0; i3--) {
            G g2 = list.get(i3);
            boolean z2 = g2.l;
            if (z2 && !g2.h) {
                list.remove(i3);
            } else if (!z2) {
                z = true;
            }
        }
        if (z) {
            recyclerView.invalidate();
        }
    }

    public abstract boolean onMove(RecyclerView recyclerView, F0 f0, F0 f02);

    /* JADX WARN: Multi-variable type inference failed */
    public void onMoved(@NonNull RecyclerView recyclerView, @NonNull F0 f0, int i, @NonNull F0 f02, int i2, int i3, int i4) {
        AbstractC1381n0 layoutManager = recyclerView.getLayoutManager();
        if (!(layoutManager instanceof K)) {
            if (layoutManager.d()) {
                if (AbstractC1381n0.A(f02.itemView) <= recyclerView.getPaddingLeft()) {
                    recyclerView.k0(i2);
                }
                if (AbstractC1381n0.D(f02.itemView) >= recyclerView.getWidth() - recyclerView.getPaddingRight()) {
                    recyclerView.k0(i2);
                }
            }
            if (layoutManager.e()) {
                if (AbstractC1381n0.E(f02.itemView) <= recyclerView.getPaddingTop()) {
                    recyclerView.k0(i2);
                }
                if (AbstractC1381n0.y(f02.itemView) >= recyclerView.getHeight() - recyclerView.getPaddingBottom()) {
                    recyclerView.k0(i2);
                    return;
                }
                return;
            }
            return;
        }
        View view = f0.itemView;
        View view2 = f02.itemView;
        LinearLayoutManager linearLayoutManager = (LinearLayoutManager) ((K) layoutManager);
        linearLayoutManager.c("Cannot drop a view during a scroll or layout calculation");
        linearLayoutManager.O0();
        linearLayoutManager.h1();
        int iK = AbstractC1381n0.K(view);
        int iK2 = AbstractC1381n0.K(view2);
        char c = iK < iK2 ? (char) 1 : (char) 65535;
        if (linearLayoutManager.u) {
            if (c == 1) {
                linearLayoutManager.j1(iK2, linearLayoutManager.r.g() - (linearLayoutManager.r.c(view) + linearLayoutManager.r.e(view2)));
                return;
            } else {
                linearLayoutManager.j1(iK2, linearLayoutManager.r.g() - linearLayoutManager.r.b(view2));
                return;
            }
        }
        if (c == 65535) {
            linearLayoutManager.j1(iK2, linearLayoutManager.r.e(view2));
        } else {
            linearLayoutManager.j1(iK2, linearLayoutManager.r.b(view2) - linearLayoutManager.r.c(view));
        }
    }

    public void onSelectedChanged(F0 f0, int i) {
    }

    public abstract void onSwiped(F0 f0, int i);
}
