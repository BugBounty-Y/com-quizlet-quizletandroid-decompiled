package androidx.recyclerview.widget;

import android.content.res.Resources;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.view.GestureDetector;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class L extends AbstractC1375k0 implements InterfaceC1385p0 {
    public Rect A;
    public long B;
    public float d;
    public float e;
    public float f;
    public float g;
    public float h;
    public float i;
    public float j;
    public float k;
    public final I m;
    public int o;
    public int q;
    public RecyclerView r;
    public VelocityTracker t;
    public ArrayList u;
    public ArrayList v;
    public GestureDetector x;
    public J y;
    public final ArrayList a = new ArrayList();
    public final float[] b = new float[2];
    public F0 c = null;
    public int l = -1;
    public int n = 0;
    public final ArrayList p = new ArrayList();
    public final RunnableC1396y s = new RunnableC1396y(this, 1);
    public View w = null;
    public final F z = new F(this);

    public L(I i) {
        this.m = i;
    }

    public static boolean m(View view, float f, float f2, float f3, float f4) {
        return f >= f3 && f <= f3 + ((float) view.getWidth()) && f2 >= f4 && f2 <= f4 + ((float) view.getHeight());
    }

    @Override // androidx.recyclerview.widget.InterfaceC1385p0
    public final void b(View view) {
        o(view);
        F0 f0O = this.r.O(view);
        if (f0O == null) {
            return;
        }
        F0 f0 = this.c;
        if (f0 != null && f0O == f0) {
            p(null, 0);
            return;
        }
        j(f0O, false);
        if (this.a.remove(f0O.itemView)) {
            this.m.clearView(this.r, f0O);
        }
    }

    @Override // androidx.recyclerview.widget.InterfaceC1385p0
    public final void c(View view) {
    }

    public final void f(RecyclerView recyclerView) {
        RecyclerView recyclerView2 = this.r;
        if (recyclerView2 == recyclerView) {
            return;
        }
        F f = this.z;
        if (recyclerView2 != null) {
            recyclerView2.g0(this);
            RecyclerView recyclerView3 = this.r;
            recyclerView3.q.remove(f);
            if (recyclerView3.r == f) {
                recyclerView3.r = null;
            }
            ArrayList arrayList = this.r.C;
            if (arrayList != null) {
                arrayList.remove(this);
            }
            ArrayList arrayList2 = this.p;
            int size = arrayList2.size();
            while (true) {
                size--;
                if (size < 0) {
                    break;
                }
                G g = (G) arrayList2.get(0);
                g.g.cancel();
                this.m.clearView(this.r, g.e);
            }
            arrayList2.clear();
            this.w = null;
            VelocityTracker velocityTracker = this.t;
            if (velocityTracker != null) {
                velocityTracker.recycle();
                this.t = null;
            }
            J j = this.y;
            if (j != null) {
                j.a = false;
                this.y = null;
            }
            if (this.x != null) {
                this.x = null;
            }
        }
        this.r = recyclerView;
        if (recyclerView != null) {
            Resources resources = recyclerView.getResources();
            this.f = resources.getDimension(R.dimen.item_touch_helper_swipe_escape_velocity);
            this.g = resources.getDimension(R.dimen.item_touch_helper_swipe_escape_max_velocity);
            this.q = ViewConfiguration.get(this.r.getContext()).getScaledTouchSlop();
            this.r.i(this);
            this.r.q.add(f);
            this.r.j(this);
            this.y = new J(this);
            this.x = new GestureDetector(this.r.getContext(), this.y);
        }
    }

    public final int g(F0 f0, int i) {
        if ((i & 12) == 0) {
            return 0;
        }
        int i2 = this.h > DefinitionKt.NO_Float_VALUE ? 8 : 4;
        VelocityTracker velocityTracker = this.t;
        I i3 = this.m;
        if (velocityTracker != null && this.l > -1) {
            velocityTracker.computeCurrentVelocity(1000, i3.getSwipeVelocityThreshold(this.g));
            float xVelocity = this.t.getXVelocity(this.l);
            float yVelocity = this.t.getYVelocity(this.l);
            int i4 = xVelocity > DefinitionKt.NO_Float_VALUE ? 8 : 4;
            float fAbs = Math.abs(xVelocity);
            if ((i4 & i) != 0 && i2 == i4 && fAbs >= i3.getSwipeEscapeVelocity(this.f) && fAbs > Math.abs(yVelocity)) {
                return i4;
            }
        }
        float swipeThreshold = i3.getSwipeThreshold(f0) * this.r.getWidth();
        if ((i & i2) == 0 || Math.abs(this.h) <= swipeThreshold) {
            return 0;
        }
        return i2;
    }

    @Override // androidx.recyclerview.widget.AbstractC1375k0
    public final void getItemOffsets(Rect rect, View view, RecyclerView recyclerView, B0 b0) {
        rect.setEmpty();
    }

    public final void h(int i, int i2, MotionEvent motionEvent) {
        int absoluteMovementFlags;
        View viewK;
        if (this.c == null && i == 2 && this.n != 2) {
            I i3 = this.m;
            if (i3.isItemViewSwipeEnabled() && this.r.getScrollState() != 1) {
                AbstractC1381n0 layoutManager = this.r.getLayoutManager();
                int i4 = this.l;
                F0 f0O = null;
                if (i4 != -1) {
                    int iFindPointerIndex = motionEvent.findPointerIndex(i4);
                    float x = motionEvent.getX(iFindPointerIndex) - this.d;
                    float y = motionEvent.getY(iFindPointerIndex) - this.e;
                    float fAbs = Math.abs(x);
                    float fAbs2 = Math.abs(y);
                    float f = this.q;
                    if ((fAbs >= f || fAbs2 >= f) && ((fAbs <= fAbs2 || !layoutManager.d()) && ((fAbs2 <= fAbs || !layoutManager.e()) && (viewK = k(motionEvent)) != null))) {
                        f0O = this.r.O(viewK);
                    }
                }
                if (f0O == null || (absoluteMovementFlags = (i3.getAbsoluteMovementFlags(this.r, f0O) & 65280) >> 8) == 0) {
                    return;
                }
                float x2 = motionEvent.getX(i2);
                float y2 = motionEvent.getY(i2);
                float f2 = x2 - this.d;
                float f3 = y2 - this.e;
                float fAbs3 = Math.abs(f2);
                float fAbs4 = Math.abs(f3);
                float f4 = this.q;
                if (fAbs3 >= f4 || fAbs4 >= f4) {
                    if (fAbs3 > fAbs4) {
                        if (f2 < DefinitionKt.NO_Float_VALUE && (absoluteMovementFlags & 4) == 0) {
                            return;
                        }
                        if (f2 > DefinitionKt.NO_Float_VALUE && (absoluteMovementFlags & 8) == 0) {
                            return;
                        }
                    } else {
                        if (f3 < DefinitionKt.NO_Float_VALUE && (absoluteMovementFlags & 1) == 0) {
                            return;
                        }
                        if (f3 > DefinitionKt.NO_Float_VALUE && (absoluteMovementFlags & 2) == 0) {
                            return;
                        }
                    }
                    this.i = DefinitionKt.NO_Float_VALUE;
                    this.h = DefinitionKt.NO_Float_VALUE;
                    this.l = motionEvent.getPointerId(0);
                    p(f0O, 1);
                }
            }
        }
    }

    public final int i(F0 f0, int i) {
        if ((i & 3) == 0) {
            return 0;
        }
        int i2 = this.i > DefinitionKt.NO_Float_VALUE ? 2 : 1;
        VelocityTracker velocityTracker = this.t;
        I i3 = this.m;
        if (velocityTracker != null && this.l > -1) {
            velocityTracker.computeCurrentVelocity(1000, i3.getSwipeVelocityThreshold(this.g));
            float xVelocity = this.t.getXVelocity(this.l);
            float yVelocity = this.t.getYVelocity(this.l);
            int i4 = yVelocity > DefinitionKt.NO_Float_VALUE ? 2 : 1;
            float fAbs = Math.abs(yVelocity);
            if ((i4 & i) != 0 && i4 == i2 && fAbs >= i3.getSwipeEscapeVelocity(this.f) && fAbs > Math.abs(xVelocity)) {
                return i4;
            }
        }
        float swipeThreshold = i3.getSwipeThreshold(f0) * this.r.getHeight();
        if ((i & i2) == 0 || Math.abs(this.i) <= swipeThreshold) {
            return 0;
        }
        return i2;
    }

    public final void j(F0 f0, boolean z) {
        ArrayList arrayList = this.p;
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            G g = (G) arrayList.get(size);
            if (g.e == f0) {
                g.k |= z;
                if (!g.l) {
                    g.g.cancel();
                }
                arrayList.remove(size);
                return;
            }
        }
    }

    public final View k(MotionEvent motionEvent) {
        float x = motionEvent.getX();
        float y = motionEvent.getY();
        F0 f0 = this.c;
        if (f0 != null) {
            View view = f0.itemView;
            if (m(view, x, y, this.j + this.h, this.k + this.i)) {
                return view;
            }
        }
        ArrayList arrayList = this.p;
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            G g = (G) arrayList.get(size);
            View view2 = g.e.itemView;
            if (m(view2, x, y, g.i, g.j)) {
                return view2;
            }
        }
        RecyclerView recyclerView = this.r;
        for (int iX = recyclerView.f.x() - 1; iX >= 0; iX--) {
            View viewW = recyclerView.f.w(iX);
            float translationX = viewW.getTranslationX();
            float translationY = viewW.getTranslationY();
            if (x >= viewW.getLeft() + translationX && x <= viewW.getRight() + translationX && y >= viewW.getTop() + translationY && y <= viewW.getBottom() + translationY) {
                return viewW;
            }
        }
        return null;
    }

    public final void l(float[] fArr) {
        if ((this.o & 12) != 0) {
            fArr[0] = (this.j + this.h) - this.c.itemView.getLeft();
        } else {
            fArr[0] = this.c.itemView.getTranslationX();
        }
        if ((this.o & 3) != 0) {
            fArr[1] = (this.k + this.i) - this.c.itemView.getTop();
        } else {
            fArr[1] = this.c.itemView.getTranslationY();
        }
    }

    public final void n(F0 f0) {
        int i;
        int i2;
        int i3;
        if (this.r.isLayoutRequested()) {
            return;
        }
        char c = 2;
        if (this.n != 2) {
            return;
        }
        I i4 = this.m;
        float moveThreshold = i4.getMoveThreshold(f0);
        int i5 = (int) (this.j + this.h);
        int i6 = (int) (this.k + this.i);
        if (Math.abs(i6 - f0.itemView.getTop()) >= f0.itemView.getHeight() * moveThreshold || Math.abs(i5 - f0.itemView.getLeft()) >= f0.itemView.getWidth() * moveThreshold) {
            ArrayList arrayList = this.u;
            if (arrayList == null) {
                this.u = new ArrayList();
                this.v = new ArrayList();
            } else {
                arrayList.clear();
                this.v.clear();
            }
            int boundingBoxMargin = i4.getBoundingBoxMargin();
            int iRound = Math.round(this.j + this.h) - boundingBoxMargin;
            int iRound2 = Math.round(this.k + this.i) - boundingBoxMargin;
            int i7 = boundingBoxMargin * 2;
            int width = f0.itemView.getWidth() + iRound + i7;
            int height = f0.itemView.getHeight() + iRound2 + i7;
            int i8 = (iRound + width) / 2;
            int i9 = (iRound2 + height) / 2;
            AbstractC1381n0 layoutManager = this.r.getLayoutManager();
            int iV = layoutManager.v();
            int i10 = 0;
            while (i10 < iV) {
                char c2 = c;
                View viewU = layoutManager.u(i10);
                if (viewU != f0.itemView && viewU.getBottom() >= iRound2 && viewU.getTop() <= height && viewU.getRight() >= iRound && viewU.getLeft() <= width) {
                    F0 f0O = this.r.O(viewU);
                    i = i8;
                    if (i4.canDropOver(this.r, this.c, f0O)) {
                        int iAbs = Math.abs(i - ((viewU.getRight() + viewU.getLeft()) / 2));
                        int iAbs2 = Math.abs(i9 - ((viewU.getBottom() + viewU.getTop()) / 2));
                        int i11 = (iAbs2 * iAbs2) + (iAbs * iAbs);
                        int size = this.u.size();
                        i2 = iRound;
                        i3 = iRound2;
                        int i12 = 0;
                        int i13 = 0;
                        while (i12 < size) {
                            int i14 = size;
                            if (i11 <= ((Integer) this.v.get(i12)).intValue()) {
                                break;
                            }
                            i13++;
                            i12++;
                            size = i14;
                        }
                        this.u.add(i13, f0O);
                        this.v.add(i13, Integer.valueOf(i11));
                    }
                    i10++;
                    c = c2;
                    iRound = i2;
                    i8 = i;
                    iRound2 = i3;
                } else {
                    i = i8;
                }
                i2 = iRound;
                i3 = iRound2;
                i10++;
                c = c2;
                iRound = i2;
                i8 = i;
                iRound2 = i3;
            }
            ArrayList arrayList2 = this.u;
            if (arrayList2.size() == 0) {
                return;
            }
            F0 f0ChooseDropTarget = i4.chooseDropTarget(f0, arrayList2, i5, i6);
            if (f0ChooseDropTarget == null) {
                this.u.clear();
                this.v.clear();
                return;
            }
            int absoluteAdapterPosition = f0ChooseDropTarget.getAbsoluteAdapterPosition();
            int absoluteAdapterPosition2 = f0.getAbsoluteAdapterPosition();
            if (i4.onMove(this.r, f0, f0ChooseDropTarget)) {
                this.m.onMoved(this.r, f0, absoluteAdapterPosition2, f0ChooseDropTarget, absoluteAdapterPosition, i5, i6);
            }
        }
    }

    public final void o(View view) {
        if (view == this.w) {
            this.w = null;
        }
    }

    @Override // androidx.recyclerview.widget.AbstractC1375k0
    public final void onDraw(Canvas canvas, RecyclerView recyclerView, B0 b0) {
        float f;
        float f2;
        if (this.c != null) {
            float[] fArr = this.b;
            l(fArr);
            float f3 = fArr[0];
            f2 = fArr[1];
            f = f3;
        } else {
            f = 0.0f;
            f2 = 0.0f;
        }
        this.m.onDraw(canvas, recyclerView, this.c, this.p, this.n, f, f2);
    }

    @Override // androidx.recyclerview.widget.AbstractC1375k0
    public final void onDrawOver(Canvas canvas, RecyclerView recyclerView, B0 b0) {
        float f;
        float f2;
        if (this.c != null) {
            float[] fArr = this.b;
            l(fArr);
            float f3 = fArr[0];
            f2 = fArr[1];
            f = f3;
        } else {
            f = 0.0f;
            f2 = 0.0f;
        }
        this.m.onDrawOver(canvas, recyclerView, this.c, this.p, this.n, f, f2);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:18:0x0047  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00b1  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x00ba A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00df  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x00f1  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00f3  */
    /* JADX WARN: Type inference failed for: r16v0 */
    /* JADX WARN: Type inference failed for: r16v1 */
    /* JADX WARN: Type inference failed for: r16v2 */
    /* JADX WARN: Type inference failed for: r16v3 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void p(androidx.recyclerview.widget.F0 r22, int r23) {
        /*
            Method dump skipped, instructions count: 415
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.L.p(androidx.recyclerview.widget.F0, int):void");
    }

    public final void q(int i, int i2, MotionEvent motionEvent) {
        float x = motionEvent.getX(i2);
        float y = motionEvent.getY(i2);
        float f = x - this.d;
        this.h = f;
        this.i = y - this.e;
        if ((i & 4) == 0) {
            this.h = Math.max(DefinitionKt.NO_Float_VALUE, f);
        }
        if ((i & 8) == 0) {
            this.h = Math.min(DefinitionKt.NO_Float_VALUE, this.h);
        }
        if ((i & 1) == 0) {
            this.i = Math.max(DefinitionKt.NO_Float_VALUE, this.i);
        }
        if ((i & 2) == 0) {
            this.i = Math.min(DefinitionKt.NO_Float_VALUE, this.i);
        }
    }
}
