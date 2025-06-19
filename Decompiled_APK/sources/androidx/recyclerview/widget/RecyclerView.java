package androidx.recyclerview.widget;

import android.R;
import android.animation.LayoutTransition;
import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.StateListDrawable;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.SystemClock;
import android.os.Trace;
import android.util.AttributeSet;
import android.util.Log;
import android.util.SparseArray;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityManager;
import android.widget.EdgeEffect;
import android.widget.OverScroller;
import androidx.annotation.NonNull;
import androidx.collection.C0210h;
import androidx.collection.C0219q;
import androidx.compose.foundation.gestures.l1;
import androidx.compose.material3.C0676l1;
import androidx.compose.ui.platform.U0;
import androidx.core.view.C1052i;
import androidx.core.view.C1060q;
import androidx.core.view.InterfaceC1059p;
import androidx.customview.view.AbsSavedState;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.G6;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.ref.WeakReference;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.WeakHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public class RecyclerView extends ViewGroup implements InterfaceC1059p {
    public static boolean M1 = false;
    public static boolean N1 = false;
    public static final int[] O1 = {R.attr.nestedScrollingEnabled};
    public static final float P1 = (float) (Math.log(0.78d) / Math.log(0.9d));
    public static final boolean Q1 = true;
    public static final boolean R1 = true;
    public static final Class[] S1;
    public static final H T1;
    public static final C0 U1;
    public boolean A;
    public C1060q A1;
    public final AccessibilityManager B;
    public final int[] B1;
    public ArrayList C;
    public final int[] C1;
    public boolean D;
    public final int[] D1;
    public boolean E;
    public final ArrayList E1;
    public int F;
    public final RunnableC1355a0 F1;
    public int G;
    public boolean G1;
    public AbstractC1371i0 H;
    public int H1;
    public EdgeEffect I;
    public int I1;
    public EdgeEffect J;
    public final boolean J1;
    public EdgeEffect K;
    public final C1357b0 K1;
    public EdgeEffect L;
    public final C1052i L1;
    public AbstractC1373j0 M;
    public int V;
    public int W;
    public final float a;
    public final x0 b;
    public final v0 c;
    public VelocityTracker c1;
    public SavedState d;
    public int d1;
    public final androidx.navigation.internal.m e;
    public int e1;
    public final androidx.camera.camera2.internal.concurrent.a f;
    public int f1;
    public final N0 g;
    public int g1;
    public boolean h;
    public int h1;
    public final RunnableC1355a0 i;
    public AbstractC1387q0 i1;
    public final Rect j;
    public final int j1;
    public final Rect k;
    public final int k1;
    public final RectF l;
    public final float l1;
    public AbstractC1361d0 m;
    public final float m1;
    public AbstractC1381n0 n;
    public boolean n1;
    public final ArrayList o;
    public final E0 o1;
    public final ArrayList p;
    public D p1;
    public final ArrayList q;
    public final C0210h q1;
    public InterfaceC1388r0 r;
    public final B0 r1;
    public boolean s;
    public AbstractC1390s0 s1;
    public boolean t;
    public ArrayList t1;
    public boolean u;
    public boolean u1;
    public int v;
    public boolean v1;
    public boolean w;
    public final C1357b0 w1;
    public boolean x;
    public boolean x1;
    public boolean y;
    public H0 y1;
    public int z;
    public final int[] z1;

    public static class SavedState extends AbsSavedState {
        public static final Parcelable.Creator<SavedState> CREATOR = new y0();
        public Parcelable c;

        public SavedState(Parcel parcel, ClassLoader classLoader) {
            super(parcel, classLoader);
            this.c = parcel.readParcelable(classLoader == null ? AbstractC1381n0.class.getClassLoader() : classLoader);
        }

        @Override // androidx.customview.view.AbsSavedState, android.os.Parcelable
        public final void writeToParcel(Parcel parcel, int i) {
            super.writeToParcel(parcel, i);
            parcel.writeParcelable(this.c, 0);
        }
    }

    static {
        Class cls = Integer.TYPE;
        S1 = new Class[]{Context.class, AttributeSet.class, cls, cls};
        T1 = new H(2);
        U1 = new C0();
    }

    public RecyclerView(@NonNull Context context) {
        this(context, null);
    }

    public static RecyclerView I(View view) {
        if (!(view instanceof ViewGroup)) {
            return null;
        }
        if (view instanceof RecyclerView) {
            return (RecyclerView) view;
        }
        ViewGroup viewGroup = (ViewGroup) view;
        int childCount = viewGroup.getChildCount();
        for (int i = 0; i < childCount; i++) {
            RecyclerView recyclerViewI = I(viewGroup.getChildAt(i));
            if (recyclerViewI != null) {
                return recyclerViewI;
            }
        }
        return null;
    }

    public static F0 P(View view) {
        if (view == null) {
            return null;
        }
        return ((C1383o0) view.getLayoutParams()).a;
    }

    private C1060q getScrollingChildHelper() {
        if (this.A1 == null) {
            this.A1 = new C1060q(this);
        }
        return this.A1;
    }

    public static void m(F0 f0) {
        WeakReference<RecyclerView> weakReference = f0.mNestedRecyclerView;
        if (weakReference != null) {
            RecyclerView recyclerView = weakReference.get();
            while (recyclerView != null) {
                if (recyclerView == f0.itemView) {
                    return;
                }
                Object parent = recyclerView.getParent();
                recyclerView = parent instanceof View ? (View) parent : null;
            }
            f0.mNestedRecyclerView = null;
        }
    }

    public static int p(int i, EdgeEffect edgeEffect, EdgeEffect edgeEffect2, int i2) {
        if (i > 0 && edgeEffect != null && androidx.core.widget.e.a(edgeEffect) != DefinitionKt.NO_Float_VALUE) {
            int iRound = Math.round(androidx.core.widget.e.b(edgeEffect, ((-i) * 4.0f) / i2, 0.5f) * ((-i2) / 4.0f));
            if (iRound != i) {
                edgeEffect.finish();
            }
            return i - iRound;
        }
        if (i >= 0 || edgeEffect2 == null || androidx.core.widget.e.a(edgeEffect2) == DefinitionKt.NO_Float_VALUE) {
            return i;
        }
        float f = i2;
        int iRound2 = Math.round(androidx.core.widget.e.b(edgeEffect2, (i * 4.0f) / f, 0.5f) * (f / 4.0f));
        if (iRound2 != i) {
            edgeEffect2.finish();
        }
        return i - iRound2;
    }

    public static void setDebugAssertionsEnabled(boolean z) {
        M1 = z;
    }

    public static void setVerboseLoggingEnabled(boolean z) {
        N1 = z;
    }

    public final void A() {
        if (this.I != null) {
            return;
        }
        ((C0) this.H).getClass();
        EdgeEffect edgeEffect = new EdgeEffect(getContext());
        this.I = edgeEffect;
        if (this.h) {
            edgeEffect.setSize((getMeasuredHeight() - getPaddingTop()) - getPaddingBottom(), (getMeasuredWidth() - getPaddingLeft()) - getPaddingRight());
        } else {
            edgeEffect.setSize(getMeasuredHeight(), getMeasuredWidth());
        }
    }

    public final void B() {
        if (this.K != null) {
            return;
        }
        ((C0) this.H).getClass();
        EdgeEffect edgeEffect = new EdgeEffect(getContext());
        this.K = edgeEffect;
        if (this.h) {
            edgeEffect.setSize((getMeasuredHeight() - getPaddingTop()) - getPaddingBottom(), (getMeasuredWidth() - getPaddingLeft()) - getPaddingRight());
        } else {
            edgeEffect.setSize(getMeasuredHeight(), getMeasuredWidth());
        }
    }

    public final void C() {
        if (this.J != null) {
            return;
        }
        ((C0) this.H).getClass();
        EdgeEffect edgeEffect = new EdgeEffect(getContext());
        this.J = edgeEffect;
        if (this.h) {
            edgeEffect.setSize((getMeasuredWidth() - getPaddingLeft()) - getPaddingRight(), (getMeasuredHeight() - getPaddingTop()) - getPaddingBottom());
        } else {
            edgeEffect.setSize(getMeasuredWidth(), getMeasuredHeight());
        }
    }

    public final String D() {
        return " " + super.toString() + ", adapter:" + this.m + ", layout:" + this.n + ", context:" + getContext();
    }

    public final void E(B0 b0) {
        if (getScrollState() != 2) {
            b0.getClass();
            return;
        }
        OverScroller overScroller = this.o1.c;
        overScroller.getFinalX();
        overScroller.getCurrX();
        b0.getClass();
        overScroller.getFinalY();
        overScroller.getCurrY();
    }

    public final View F(View view) {
        ViewParent parent = view.getParent();
        while (parent != null && parent != this && (parent instanceof View)) {
            view = parent;
            parent = view.getParent();
        }
        if (parent == this) {
            return view;
        }
        return null;
    }

    public final boolean G(MotionEvent motionEvent) {
        int action = motionEvent.getAction();
        ArrayList arrayList = this.q;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            InterfaceC1388r0 interfaceC1388r0 = (InterfaceC1388r0) arrayList.get(i);
            if (interfaceC1388r0.d(motionEvent) && action != 3) {
                this.r = interfaceC1388r0;
                return true;
            }
        }
        return false;
    }

    public final void H(int[] iArr) {
        int iX = this.f.x();
        if (iX == 0) {
            iArr[0] = -1;
            iArr[1] = -1;
            return;
        }
        int i = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        int i2 = Integer.MIN_VALUE;
        for (int i3 = 0; i3 < iX; i3++) {
            F0 f0P = P(this.f.w(i3));
            if (!f0P.shouldIgnore()) {
                int layoutPosition = f0P.getLayoutPosition();
                if (layoutPosition < i) {
                    i = layoutPosition;
                }
                if (layoutPosition > i2) {
                    i2 = layoutPosition;
                }
            }
        }
        iArr[0] = i;
        iArr[1] = i2;
    }

    public final F0 J(int i) {
        F0 f0 = null;
        if (this.D) {
            return null;
        }
        int iC = this.f.C();
        for (int i2 = 0; i2 < iC; i2++) {
            F0 f0P = P(this.f.B(i2));
            if (f0P != null && !f0P.isRemoved() && M(f0P) == i) {
                androidx.camera.camera2.internal.concurrent.a aVar = this.f;
                if (!((ArrayList) aVar.c).contains(f0P.itemView)) {
                    return f0P;
                }
                f0 = f0P;
            }
        }
        return f0;
    }

    public boolean K(int i, int i2) {
        return L(i, i2, this.j1, this.k1);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:109:0x016f  */
    /* JADX WARN: Removed duplicated region for block: B:167:0x022d A[PHI: r17 r18 r22
  0x022d: PHI (r17v4 boolean) = 
  (r17v2 boolean)
  (r17v2 boolean)
  (r17v2 boolean)
  (r17v2 boolean)
  (r17v2 boolean)
  (r17v2 boolean)
  (r17v6 boolean)
  (r17v6 boolean)
  (r17v6 boolean)
  (r17v7 boolean)
 binds: [B:169:0x0239, B:172:0x0240, B:175:0x0247, B:178:0x024e, B:181:0x025a, B:198:0x0294, B:147:0x01f7, B:163:0x0225, B:164:0x0227, B:109:0x016f] A[DONT_GENERATE, DONT_INLINE]
  0x022d: PHI (r18v4 boolean) = 
  (r18v2 boolean)
  (r18v2 boolean)
  (r18v2 boolean)
  (r18v2 boolean)
  (r18v2 boolean)
  (r18v2 boolean)
  (r18v5 boolean)
  (r18v5 boolean)
  (r18v5 boolean)
  (r18v9 boolean)
 binds: [B:169:0x0239, B:172:0x0240, B:175:0x0247, B:178:0x024e, B:181:0x025a, B:198:0x0294, B:147:0x01f7, B:163:0x0225, B:164:0x0227, B:109:0x016f] A[DONT_GENERATE, DONT_INLINE]
  0x022d: PHI (r22v5 boolean) = 
  (r22v3 boolean)
  (r22v3 boolean)
  (r22v3 boolean)
  (r22v3 boolean)
  (r22v3 boolean)
  (r22v3 boolean)
  (r22v6 boolean)
  (r22v6 boolean)
  (r22v6 boolean)
  (r22v8 boolean)
 binds: [B:169:0x0239, B:172:0x0240, B:175:0x0247, B:178:0x024e, B:181:0x025a, B:198:0x0294, B:147:0x01f7, B:163:0x0225, B:164:0x0227, B:109:0x016f] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:212:0x02aa  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x008a  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00c9  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x00d0 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:65:0x00d2  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x00f2  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x00fa  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x0140  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean L(int r20, int r21, int r22, int r23) {
        /*
            Method dump skipped, instructions count: 730
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.RecyclerView.L(int, int, int, int):boolean");
    }

    public final int M(F0 f0) {
        if (f0.hasAnyOfTheFlags(524) || !f0.isBound()) {
            return -1;
        }
        androidx.navigation.internal.m mVar = this.e;
        int i = f0.mPosition;
        ArrayList arrayList = (ArrayList) mVar.b;
        int size = arrayList.size();
        for (int i2 = 0; i2 < size; i2++) {
            C1354a c1354a = (C1354a) arrayList.get(i2);
            int i3 = c1354a.a;
            if (i3 != 1) {
                if (i3 == 2) {
                    int i4 = c1354a.b;
                    if (i4 <= i) {
                        int i5 = c1354a.d;
                        if (i4 + i5 > i) {
                            return -1;
                        }
                        i -= i5;
                    } else {
                        continue;
                    }
                } else if (i3 == 8) {
                    int i6 = c1354a.b;
                    if (i6 == i) {
                        i = c1354a.d;
                    } else {
                        if (i6 < i) {
                            i--;
                        }
                        if (c1354a.d <= i) {
                            i++;
                        }
                    }
                }
            } else if (c1354a.b <= i) {
                i += c1354a.d;
            }
        }
        return i;
    }

    public final long N(F0 f0) {
        return this.m.hasStableIds() ? f0.getItemId() : f0.mPosition;
    }

    public final F0 O(View view) {
        ViewParent parent = view.getParent();
        if (parent == null || parent == this) {
            return P(view);
        }
        throw new IllegalArgumentException("View " + view + " is not a direct child of " + this);
    }

    public final Rect Q(View view) {
        C1383o0 c1383o0 = (C1383o0) view.getLayoutParams();
        boolean z = c1383o0.c;
        Rect rect = c1383o0.b;
        if (z) {
            B0 b0 = this.r1;
            if (!b0.g || (!c1383o0.a.isUpdated() && !c1383o0.a.isInvalid())) {
                rect.set(0, 0, 0, 0);
                ArrayList arrayList = this.p;
                int size = arrayList.size();
                for (int i = 0; i < size; i++) {
                    Rect rect2 = this.j;
                    rect2.set(0, 0, 0, 0);
                    ((AbstractC1375k0) arrayList.get(i)).getItemOffsets(rect2, view, this, b0);
                    rect.left += rect2.left;
                    rect.top += rect2.top;
                    rect.right += rect2.right;
                    rect.bottom += rect2.bottom;
                }
                c1383o0.c = false;
                return rect;
            }
        }
        return rect;
    }

    public final boolean R() {
        return !this.u || this.D || this.e.h();
    }

    public final boolean S() {
        return this.F > 0;
    }

    public final void T(int i) {
        if (this.n == null) {
            return;
        }
        setScrollState(2);
        this.n.v0(i);
        awakenScrollBars();
    }

    public final void U() {
        int iC = this.f.C();
        for (int i = 0; i < iC; i++) {
            ((C1383o0) this.f.B(i).getLayoutParams()).c = true;
        }
        ArrayList arrayList = this.c.c;
        int size = arrayList.size();
        for (int i2 = 0; i2 < size; i2++) {
            C1383o0 c1383o0 = (C1383o0) ((F0) arrayList.get(i2)).itemView.getLayoutParams();
            if (c1383o0 != null) {
                c1383o0.c = true;
            }
        }
    }

    public final void V(int i, int i2, boolean z) {
        int i3 = i + i2;
        int iC = this.f.C();
        for (int i4 = 0; i4 < iC; i4++) {
            F0 f0P = P(this.f.B(i4));
            if (f0P != null && !f0P.shouldIgnore()) {
                int i5 = f0P.mPosition;
                B0 b0 = this.r1;
                if (i5 >= i3) {
                    if (N1) {
                        f0P.toString();
                    }
                    f0P.offsetPosition(-i2, z);
                    b0.f = true;
                } else if (i5 >= i) {
                    if (N1) {
                        f0P.toString();
                    }
                    f0P.flagRemovedAndOffsetPosition(i - 1, -i2, z);
                    b0.f = true;
                }
            }
        }
        v0 v0Var = this.c;
        ArrayList arrayList = v0Var.c;
        for (int size = arrayList.size() - 1; size >= 0; size--) {
            F0 f0 = (F0) arrayList.get(size);
            if (f0 != null) {
                int i6 = f0.mPosition;
                if (i6 >= i3) {
                    if (N1) {
                        f0.toString();
                    }
                    f0.offsetPosition(-i2, z);
                } else if (i6 >= i) {
                    f0.addFlags(8);
                    v0Var.g(size);
                }
            }
        }
        requestLayout();
    }

    public final void W() {
        this.F++;
    }

    public final void X(boolean z) {
        int i;
        AccessibilityManager accessibilityManager;
        int i2 = this.F - 1;
        this.F = i2;
        if (i2 < 1) {
            if (M1 && i2 < 0) {
                throw new IllegalStateException(androidx.compose.ui.node.B.c(this, new StringBuilder("layout or scroll counter cannot go below zero.Some calls are not matching")));
            }
            this.F = 0;
            if (z) {
                int i3 = this.z;
                this.z = 0;
                if (i3 != 0 && (accessibilityManager = this.B) != null && accessibilityManager.isEnabled()) {
                    AccessibilityEvent accessibilityEventObtain = AccessibilityEvent.obtain();
                    accessibilityEventObtain.setEventType(2048);
                    accessibilityEventObtain.setContentChangeTypes(i3);
                    sendAccessibilityEventUnchecked(accessibilityEventObtain);
                }
                ArrayList arrayList = this.E1;
                for (int size = arrayList.size() - 1; size >= 0; size--) {
                    F0 f0 = (F0) arrayList.get(size);
                    if (f0.itemView.getParent() == this && !f0.shouldIgnore() && (i = f0.mPendingAccessibilityState) != -1) {
                        f0.itemView.setImportantForAccessibility(i);
                        f0.mPendingAccessibilityState = -1;
                    }
                }
                arrayList.clear();
            }
        }
    }

    public final void Y(MotionEvent motionEvent) {
        int actionIndex = motionEvent.getActionIndex();
        if (motionEvent.getPointerId(actionIndex) == this.W) {
            int i = actionIndex == 0 ? 1 : 0;
            this.W = motionEvent.getPointerId(i);
            int x = (int) (motionEvent.getX(i) + 0.5f);
            this.f1 = x;
            this.d1 = x;
            int y = (int) (motionEvent.getY(i) + 0.5f);
            this.g1 = y;
            this.e1 = y;
        }
    }

    public final void Z() {
        if (this.x1 || !this.s) {
            return;
        }
        WeakHashMap weakHashMap = androidx.core.view.V.a;
        postOnAnimation(this.F1);
        this.x1 = true;
    }

    public final void a0() {
        boolean z;
        boolean z2 = false;
        if (this.D) {
            androidx.navigation.internal.m mVar = this.e;
            mVar.m((ArrayList) mVar.b);
            mVar.m((ArrayList) mVar.e);
            mVar.c = 0;
            if (this.E) {
                this.n.d0();
            }
        }
        if (this.M == null || !this.n.H0()) {
            this.e.d();
        } else {
            this.e.l();
        }
        boolean z3 = this.u1 || this.v1;
        boolean z4 = this.u && this.M != null && ((z = this.D) || z3 || this.n.f) && (!z || this.m.hasStableIds());
        B0 b0 = this.r1;
        b0.j = z4;
        if (z4 && z3 && !this.D && this.M != null && this.n.H0()) {
            z2 = true;
        }
        b0.k = z2;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void addFocusables(ArrayList arrayList, int i, int i2) {
        AbstractC1381n0 abstractC1381n0 = this.n;
        if (abstractC1381n0 != null) {
            abstractC1381n0.getClass();
        }
        super.addFocusables(arrayList, i, i2);
    }

    public final void b0(boolean z) {
        this.E = z | this.E;
        this.D = true;
        int iC = this.f.C();
        for (int i = 0; i < iC; i++) {
            F0 f0P = P(this.f.B(i));
            if (f0P != null && !f0P.shouldIgnore()) {
                f0P.addFlags(6);
            }
        }
        U();
        v0 v0Var = this.c;
        ArrayList arrayList = v0Var.c;
        int size = arrayList.size();
        for (int i2 = 0; i2 < size; i2++) {
            F0 f0 = (F0) arrayList.get(i2);
            if (f0 != null) {
                f0.addFlags(6);
                f0.addChangePayload(null);
            }
        }
        AbstractC1361d0 abstractC1361d0 = v0Var.h.m;
        if (abstractC1361d0 == null || !abstractC1361d0.hasStableIds()) {
            v0Var.f();
        }
    }

    public final void c0(F0 f0, C0676l1 c0676l1) {
        f0.setFlags(0, 8192);
        boolean z = this.r1.h;
        N0 n0 = this.g;
        if (z && f0.isUpdated() && !f0.isRemoved() && !f0.shouldIgnore()) {
            ((C0219q) n0.b).g(N(f0), f0);
        }
        androidx.collection.V v = (androidx.collection.V) n0.a;
        Q0 q0A = (Q0) v.get(f0);
        if (q0A == null) {
            q0A = Q0.a();
            v.put(f0, q0A);
        }
        q0A.b = c0676l1;
        q0A.a |= 4;
    }

    @Override // android.view.ViewGroup
    public final boolean checkLayoutParams(ViewGroup.LayoutParams layoutParams) {
        return (layoutParams instanceof C1383o0) && this.n.f((C1383o0) layoutParams);
    }

    @Override // android.view.View
    public final int computeHorizontalScrollExtent() {
        AbstractC1381n0 abstractC1381n0 = this.n;
        if (abstractC1381n0 != null && abstractC1381n0.d()) {
            return this.n.j(this.r1);
        }
        return 0;
    }

    @Override // android.view.View
    public final int computeHorizontalScrollOffset() {
        AbstractC1381n0 abstractC1381n0 = this.n;
        if (abstractC1381n0 != null && abstractC1381n0.d()) {
            return this.n.k(this.r1);
        }
        return 0;
    }

    @Override // android.view.View
    public final int computeHorizontalScrollRange() {
        AbstractC1381n0 abstractC1381n0 = this.n;
        if (abstractC1381n0 != null && abstractC1381n0.d()) {
            return this.n.l(this.r1);
        }
        return 0;
    }

    @Override // android.view.View
    public final int computeVerticalScrollExtent() {
        AbstractC1381n0 abstractC1381n0 = this.n;
        if (abstractC1381n0 != null && abstractC1381n0.e()) {
            return this.n.m(this.r1);
        }
        return 0;
    }

    @Override // android.view.View
    public final int computeVerticalScrollOffset() {
        AbstractC1381n0 abstractC1381n0 = this.n;
        if (abstractC1381n0 != null && abstractC1381n0.e()) {
            return this.n.n(this.r1);
        }
        return 0;
    }

    @Override // android.view.View
    public final int computeVerticalScrollRange() {
        AbstractC1381n0 abstractC1381n0 = this.n;
        if (abstractC1381n0 != null && abstractC1381n0.e()) {
            return this.n.o(this.r1);
        }
        return 0;
    }

    public final void d0() {
        boolean zIsFinished;
        EdgeEffect edgeEffect = this.I;
        if (edgeEffect != null) {
            edgeEffect.onRelease();
            zIsFinished = this.I.isFinished();
        } else {
            zIsFinished = false;
        }
        EdgeEffect edgeEffect2 = this.J;
        if (edgeEffect2 != null) {
            edgeEffect2.onRelease();
            zIsFinished |= this.J.isFinished();
        }
        EdgeEffect edgeEffect3 = this.K;
        if (edgeEffect3 != null) {
            edgeEffect3.onRelease();
            zIsFinished |= this.K.isFinished();
        }
        EdgeEffect edgeEffect4 = this.L;
        if (edgeEffect4 != null) {
            edgeEffect4.onRelease();
            zIsFinished |= this.L.isFinished();
        }
        if (zIsFinished) {
            postInvalidateOnAnimation();
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public final boolean dispatchKeyEvent(KeyEvent keyEvent) {
        if (super.dispatchKeyEvent(keyEvent)) {
            return true;
        }
        AbstractC1381n0 layoutManager = getLayoutManager();
        int itemCount = 0;
        if (layoutManager != null) {
            if (layoutManager.e()) {
                int keyCode = keyEvent.getKeyCode();
                if (keyCode == 92 || keyCode == 93) {
                    int measuredHeight = getMeasuredHeight();
                    if (keyCode == 93) {
                        m0(0, measuredHeight, false);
                        return true;
                    }
                    m0(0, -measuredHeight, false);
                    return true;
                }
                if (keyCode == 122 || keyCode == 123) {
                    boolean zP = layoutManager.P();
                    if (keyCode == 122) {
                        if (zP) {
                            itemCount = getAdapter().getItemCount();
                        }
                    } else if (!zP) {
                        itemCount = getAdapter().getItemCount();
                    }
                    n0(itemCount);
                    return true;
                }
            } else if (layoutManager.d()) {
                int keyCode2 = keyEvent.getKeyCode();
                if (keyCode2 == 92 || keyCode2 == 93) {
                    int measuredWidth = getMeasuredWidth();
                    if (keyCode2 == 93) {
                        m0(measuredWidth, 0, false);
                        return true;
                    }
                    m0(-measuredWidth, 0, false);
                    return true;
                }
                if (keyCode2 == 122 || keyCode2 == 123) {
                    boolean zP2 = layoutManager.P();
                    if (keyCode2 == 122) {
                        if (zP2) {
                            itemCount = getAdapter().getItemCount();
                        }
                    } else if (!zP2) {
                        itemCount = getAdapter().getItemCount();
                    }
                    n0(itemCount);
                    return true;
                }
            }
        }
        return false;
    }

    @Override // android.view.View
    public final boolean dispatchNestedFling(float f, float f2, boolean z) {
        return getScrollingChildHelper().a(f, f2, z);
    }

    @Override // android.view.View
    public final boolean dispatchNestedPreFling(float f, float f2) {
        return getScrollingChildHelper().b(f, f2);
    }

    @Override // android.view.View
    public final boolean dispatchNestedPreScroll(int i, int i2, int[] iArr, int[] iArr2) {
        return getScrollingChildHelper().c(i, i2, 0, iArr, iArr2);
    }

    @Override // android.view.View
    public final boolean dispatchNestedScroll(int i, int i2, int i3, int i4, int[] iArr) {
        return getScrollingChildHelper().d(i, i2, i3, i4, iArr, 0, null);
    }

    @Override // android.view.View
    public final boolean dispatchPopulateAccessibilityEvent(AccessibilityEvent accessibilityEvent) {
        onPopulateAccessibilityEvent(accessibilityEvent);
        return true;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void dispatchRestoreInstanceState(SparseArray sparseArray) {
        dispatchThawSelfOnly(sparseArray);
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void dispatchSaveInstanceState(SparseArray sparseArray) {
        dispatchFreezeSelfOnly(sparseArray);
    }

    @Override // android.view.View
    public final void draw(Canvas canvas) {
        boolean z;
        super.draw(canvas);
        ArrayList arrayList = this.p;
        int size = arrayList.size();
        boolean z2 = false;
        for (int i = 0; i < size; i++) {
            ((AbstractC1375k0) arrayList.get(i)).onDrawOver(canvas, this, this.r1);
        }
        EdgeEffect edgeEffect = this.I;
        if (edgeEffect == null || edgeEffect.isFinished()) {
            z = false;
        } else {
            int iSave = canvas.save();
            int paddingBottom = this.h ? getPaddingBottom() : 0;
            canvas.rotate(270.0f);
            canvas.translate((-getHeight()) + paddingBottom, DefinitionKt.NO_Float_VALUE);
            EdgeEffect edgeEffect2 = this.I;
            z = edgeEffect2 != null && edgeEffect2.draw(canvas);
            canvas.restoreToCount(iSave);
        }
        EdgeEffect edgeEffect3 = this.J;
        if (edgeEffect3 != null && !edgeEffect3.isFinished()) {
            int iSave2 = canvas.save();
            if (this.h) {
                canvas.translate(getPaddingLeft(), getPaddingTop());
            }
            EdgeEffect edgeEffect4 = this.J;
            z |= edgeEffect4 != null && edgeEffect4.draw(canvas);
            canvas.restoreToCount(iSave2);
        }
        EdgeEffect edgeEffect5 = this.K;
        if (edgeEffect5 != null && !edgeEffect5.isFinished()) {
            int iSave3 = canvas.save();
            int width = getWidth();
            int paddingTop = this.h ? getPaddingTop() : 0;
            canvas.rotate(90.0f);
            canvas.translate(paddingTop, -width);
            EdgeEffect edgeEffect6 = this.K;
            z |= edgeEffect6 != null && edgeEffect6.draw(canvas);
            canvas.restoreToCount(iSave3);
        }
        EdgeEffect edgeEffect7 = this.L;
        if (edgeEffect7 != null && !edgeEffect7.isFinished()) {
            int iSave4 = canvas.save();
            canvas.rotate(180.0f);
            if (this.h) {
                canvas.translate(getPaddingRight() + (-getWidth()), getPaddingBottom() + (-getHeight()));
            } else {
                canvas.translate(-getWidth(), -getHeight());
            }
            EdgeEffect edgeEffect8 = this.L;
            if (edgeEffect8 != null && edgeEffect8.draw(canvas)) {
                z2 = true;
            }
            z |= z2;
            canvas.restoreToCount(iSave4);
        }
        if ((z || this.M == null || arrayList.size() <= 0 || !this.M.f()) ? z : true) {
            postInvalidateOnAnimation();
        }
    }

    @Override // android.view.ViewGroup
    public final boolean drawChild(Canvas canvas, View view, long j) {
        return super.drawChild(canvas, view, j);
    }

    public final int e0(float f, int i) {
        float height = f / getHeight();
        float width = i / getWidth();
        EdgeEffect edgeEffect = this.I;
        float f2 = DefinitionKt.NO_Float_VALUE;
        if (edgeEffect == null || androidx.core.widget.e.a(edgeEffect) == DefinitionKt.NO_Float_VALUE) {
            EdgeEffect edgeEffect2 = this.K;
            if (edgeEffect2 != null && androidx.core.widget.e.a(edgeEffect2) != DefinitionKt.NO_Float_VALUE) {
                if (canScrollHorizontally(1)) {
                    this.K.onRelease();
                } else {
                    float fB = androidx.core.widget.e.b(this.K, width, height);
                    if (androidx.core.widget.e.a(this.K) == DefinitionKt.NO_Float_VALUE) {
                        this.K.onRelease();
                    }
                    f2 = fB;
                }
                invalidate();
            }
        } else {
            if (canScrollHorizontally(-1)) {
                this.I.onRelease();
            } else {
                float f3 = -androidx.core.widget.e.b(this.I, -width, 1.0f - height);
                if (androidx.core.widget.e.a(this.I) == DefinitionKt.NO_Float_VALUE) {
                    this.I.onRelease();
                }
                f2 = f3;
            }
            invalidate();
        }
        return Math.round(f2 * getWidth());
    }

    public final int f0(float f, int i) {
        float width = f / getWidth();
        float height = i / getHeight();
        EdgeEffect edgeEffect = this.J;
        float f2 = DefinitionKt.NO_Float_VALUE;
        if (edgeEffect == null || androidx.core.widget.e.a(edgeEffect) == DefinitionKt.NO_Float_VALUE) {
            EdgeEffect edgeEffect2 = this.L;
            if (edgeEffect2 != null && androidx.core.widget.e.a(edgeEffect2) != DefinitionKt.NO_Float_VALUE) {
                if (canScrollVertically(1)) {
                    this.L.onRelease();
                } else {
                    float fB = androidx.core.widget.e.b(this.L, height, 1.0f - width);
                    if (androidx.core.widget.e.a(this.L) == DefinitionKt.NO_Float_VALUE) {
                        this.L.onRelease();
                    }
                    f2 = fB;
                }
                invalidate();
            }
        } else {
            if (canScrollVertically(-1)) {
                this.J.onRelease();
            } else {
                float f3 = -androidx.core.widget.e.b(this.J, -height, width);
                if (androidx.core.widget.e.a(this.J) == DefinitionKt.NO_Float_VALUE) {
                    this.J.onRelease();
                }
                f2 = f3;
            }
            invalidate();
        }
        return Math.round(f2 * getHeight());
    }

    /* JADX WARN: Removed duplicated region for block: B:118:0x0167  */
    /* JADX WARN: Removed duplicated region for block: B:137:0x0197 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:138:0x0198  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0061  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0063  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0066  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0068  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x006c  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x006f  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0076  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0078  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x007b  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00b7  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x00ce A[ADDED_TO_REGION] */
    @Override // android.view.ViewGroup, android.view.ViewParent
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.view.View focusSearch(android.view.View r17, int r18) {
        /*
            Method dump skipped, instructions count: 413
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.RecyclerView.focusSearch(android.view.View, int):android.view.View");
    }

    public final void g0(AbstractC1375k0 abstractC1375k0) {
        AbstractC1381n0 abstractC1381n0 = this.n;
        if (abstractC1381n0 != null) {
            abstractC1381n0.c("Cannot remove item decoration during a scroll  or layout");
        }
        ArrayList arrayList = this.p;
        arrayList.remove(abstractC1375k0);
        if (arrayList.isEmpty()) {
            setWillNotDraw(getOverScrollMode() == 2);
        }
        U();
        requestLayout();
    }

    @Override // android.view.ViewGroup
    public final ViewGroup.LayoutParams generateDefaultLayoutParams() {
        AbstractC1381n0 abstractC1381n0 = this.n;
        if (abstractC1381n0 != null) {
            return abstractC1381n0.r();
        }
        throw new IllegalStateException(androidx.compose.ui.node.B.c(this, new StringBuilder("RecyclerView has no LayoutManager")));
    }

    @Override // android.view.ViewGroup
    public final ViewGroup.LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        AbstractC1381n0 abstractC1381n0 = this.n;
        if (abstractC1381n0 != null) {
            return abstractC1381n0.s(getContext(), attributeSet);
        }
        throw new IllegalStateException(androidx.compose.ui.node.B.c(this, new StringBuilder("RecyclerView has no LayoutManager")));
    }

    @Override // android.view.ViewGroup, android.view.View
    public CharSequence getAccessibilityClassName() {
        return "androidx.recyclerview.widget.RecyclerView";
    }

    public AbstractC1361d0 getAdapter() {
        return this.m;
    }

    @Override // android.view.View
    public int getBaseline() {
        AbstractC1381n0 abstractC1381n0 = this.n;
        if (abstractC1381n0 == null) {
            return super.getBaseline();
        }
        abstractC1381n0.getClass();
        return -1;
    }

    @Override // android.view.ViewGroup
    public final int getChildDrawingOrder(int i, int i2) {
        return super.getChildDrawingOrder(i, i2);
    }

    @Override // android.view.ViewGroup
    public boolean getClipToPadding() {
        return this.h;
    }

    public H0 getCompatAccessibilityDelegate() {
        return this.y1;
    }

    @NonNull
    public AbstractC1371i0 getEdgeEffectFactory() {
        return this.H;
    }

    public AbstractC1373j0 getItemAnimator() {
        return this.M;
    }

    public int getItemDecorationCount() {
        return this.p.size();
    }

    public AbstractC1381n0 getLayoutManager() {
        return this.n;
    }

    public int getMaxFlingVelocity() {
        return this.k1;
    }

    public int getMinFlingVelocity() {
        return this.j1;
    }

    public long getNanoTime() {
        if (R1) {
            return System.nanoTime();
        }
        return 0L;
    }

    public AbstractC1387q0 getOnFlingListener() {
        return this.i1;
    }

    public boolean getPreserveFocusAfterLayout() {
        return this.n1;
    }

    @NonNull
    public u0 getRecycledViewPool() {
        return this.c.c();
    }

    public int getScrollState() {
        return this.V;
    }

    public final void h(F0 f0) {
        View view = f0.itemView;
        boolean z = view.getParent() == this;
        this.c.l(O(view));
        if (f0.isTmpDetached()) {
            this.f.d(view, -1, view.getLayoutParams(), true);
            return;
        }
        if (!z) {
            this.f.b(view, -1, true);
            return;
        }
        androidx.camera.camera2.internal.concurrent.a aVar = this.f;
        int iIndexOfChild = ((C1357b0) aVar.d).a.indexOfChild(view);
        if (iIndexOfChild >= 0) {
            ((l1) aVar.e).H(iIndexOfChild);
            aVar.E(view);
        } else {
            throw new IllegalArgumentException("view is not a child, cannot hide " + view);
        }
    }

    public final void h0(View view, View view2) {
        View view3 = view2 != null ? view2 : view;
        int width = view3.getWidth();
        int height = view3.getHeight();
        Rect rect = this.j;
        rect.set(0, 0, width, height);
        ViewGroup.LayoutParams layoutParams = view3.getLayoutParams();
        if (layoutParams instanceof C1383o0) {
            C1383o0 c1383o0 = (C1383o0) layoutParams;
            if (!c1383o0.c) {
                int i = rect.left;
                Rect rect2 = c1383o0.b;
                rect.left = i - rect2.left;
                rect.right += rect2.right;
                rect.top -= rect2.top;
                rect.bottom += rect2.bottom;
            }
        }
        if (view2 != null) {
            offsetDescendantRectToMyCoords(view2, rect);
            offsetRectIntoDescendantCoords(view, rect);
        }
        this.n.s0(this, view, this.j, !this.u, view2 == null);
    }

    @Override // android.view.View
    public final boolean hasNestedScrollingParent() {
        return getScrollingChildHelper().f(0);
    }

    public final void i(AbstractC1375k0 abstractC1375k0) {
        AbstractC1381n0 abstractC1381n0 = this.n;
        if (abstractC1381n0 != null) {
            abstractC1381n0.c("Cannot add item decoration during a scroll  or layout");
        }
        ArrayList arrayList = this.p;
        if (arrayList.isEmpty()) {
            setWillNotDraw(false);
        }
        arrayList.add(abstractC1375k0);
        U();
        requestLayout();
    }

    /* JADX WARN: Removed duplicated region for block: B:30:0x00cb  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x00e3  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x0100  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0108  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean i0(int r19, int r20, android.view.MotionEvent r21, int r22) {
        /*
            Method dump skipped, instructions count: 322
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.RecyclerView.i0(int, int, android.view.MotionEvent, int):boolean");
    }

    @Override // android.view.View
    public final boolean isAttachedToWindow() {
        return this.s;
    }

    @Override // android.view.ViewGroup
    public final boolean isLayoutSuppressed() {
        return this.x;
    }

    @Override // android.view.View
    public final boolean isNestedScrollingEnabled() {
        return getScrollingChildHelper().d;
    }

    public final void j(InterfaceC1385p0 interfaceC1385p0) {
        if (this.C == null) {
            this.C = new ArrayList();
        }
        this.C.add(interfaceC1385p0);
    }

    public final void j0(int i, int i2, int[] iArr) {
        F0 f0;
        o0();
        W();
        Trace.beginSection("RV Scroll");
        B0 b0 = this.r1;
        E(b0);
        v0 v0Var = this.c;
        int iU0 = i != 0 ? this.n.u0(i, v0Var, b0) : 0;
        int iW0 = i2 != 0 ? this.n.w0(i2, v0Var, b0) : 0;
        Trace.endSection();
        int iX = this.f.x();
        for (int i3 = 0; i3 < iX; i3++) {
            View viewW = this.f.w(i3);
            F0 f0O = O(viewW);
            if (f0O != null && (f0 = f0O.mShadowingHolder) != null) {
                View view = f0.itemView;
                int left = viewW.getLeft();
                int top = viewW.getTop();
                if (left != view.getLeft() || top != view.getTop()) {
                    view.layout(left, top, view.getWidth() + left, view.getHeight() + top);
                }
            }
        }
        X(true);
        q0(false);
        if (iArr != null) {
            iArr[0] = iU0;
            iArr[1] = iW0;
        }
    }

    public final void k(AbstractC1390s0 abstractC1390s0) {
        if (this.t1 == null) {
            this.t1 = new ArrayList();
        }
        this.t1.add(abstractC1390s0);
    }

    public final void k0(int i) {
        if (this.x) {
            return;
        }
        s0();
        AbstractC1381n0 abstractC1381n0 = this.n;
        if (abstractC1381n0 == null) {
            Log.e("RecyclerView", "Cannot scroll to position a LayoutManager set. Call setLayoutManager with a non-null argument.");
        } else {
            abstractC1381n0.v0(i);
            awakenScrollBars();
        }
    }

    public final void l(String str) {
        if (S()) {
            if (str != null) {
                throw new IllegalStateException(str);
            }
            throw new IllegalStateException(androidx.compose.ui.node.B.c(this, new StringBuilder("Cannot call this method while RecyclerView is computing a layout or scrolling")));
        }
        if (this.G > 0) {
            Log.w("RecyclerView", "Cannot call this method in a scroll callback. Scroll callbacks mightbe run during a measure & layout pass where you cannot change theRecyclerView data. Any method call that might change the structureof the RecyclerView or the adapter contents should be postponed tothe next frame.", new IllegalStateException(androidx.compose.ui.node.B.c(this, new StringBuilder(""))));
        }
    }

    public final boolean l0(EdgeEffect edgeEffect, int i, int i2) {
        if (i > 0) {
            return true;
        }
        float fA = androidx.core.widget.e.a(edgeEffect) * i2;
        float fAbs = Math.abs(-i) * 0.35f;
        float f = this.a * 0.015f;
        double dLog = Math.log(fAbs / f);
        double d = P1;
        return ((float) (Math.exp((d / (d - 1.0d)) * dLog) * ((double) f))) < fA;
    }

    public final void m0(int i, int i2, boolean z) {
        AbstractC1381n0 abstractC1381n0 = this.n;
        if (abstractC1381n0 == null) {
            Log.e("RecyclerView", "Cannot smooth scroll without a LayoutManager set. Call setLayoutManager with a non-null argument.");
            return;
        }
        if (this.x) {
            return;
        }
        if (!abstractC1381n0.d()) {
            i = 0;
        }
        if (!this.n.e()) {
            i2 = 0;
        }
        if (i == 0 && i2 == 0) {
            return;
        }
        if (z) {
            int i3 = i != 0 ? 1 : 0;
            if (i2 != 0) {
                i3 |= 2;
            }
            getScrollingChildHelper().h(i3, 1);
        }
        this.o1.c(i, i2, Integer.MIN_VALUE, null);
    }

    public final void n() {
        int iC = this.f.C();
        for (int i = 0; i < iC; i++) {
            F0 f0P = P(this.f.B(i));
            if (!f0P.shouldIgnore()) {
                f0P.clearOldPosition();
            }
        }
        v0 v0Var = this.c;
        ArrayList arrayList = v0Var.c;
        int size = arrayList.size();
        for (int i2 = 0; i2 < size; i2++) {
            ((F0) arrayList.get(i2)).clearOldPosition();
        }
        ArrayList arrayList2 = v0Var.a;
        int size2 = arrayList2.size();
        for (int i3 = 0; i3 < size2; i3++) {
            ((F0) arrayList2.get(i3)).clearOldPosition();
        }
        ArrayList arrayList3 = v0Var.b;
        if (arrayList3 != null) {
            int size3 = arrayList3.size();
            for (int i4 = 0; i4 < size3; i4++) {
                ((F0) v0Var.b.get(i4)).clearOldPosition();
            }
        }
    }

    public final void n0(int i) {
        if (this.x) {
            return;
        }
        AbstractC1381n0 abstractC1381n0 = this.n;
        if (abstractC1381n0 == null) {
            Log.e("RecyclerView", "Cannot smooth scroll without a LayoutManager set. Call setLayoutManager with a non-null argument.");
        } else {
            abstractC1381n0.F0(this, this.r1, i);
        }
    }

    public final void o(int i, int i2) {
        boolean zIsFinished;
        EdgeEffect edgeEffect = this.I;
        if (edgeEffect == null || edgeEffect.isFinished() || i <= 0) {
            zIsFinished = false;
        } else {
            this.I.onRelease();
            zIsFinished = this.I.isFinished();
        }
        EdgeEffect edgeEffect2 = this.K;
        if (edgeEffect2 != null && !edgeEffect2.isFinished() && i < 0) {
            this.K.onRelease();
            zIsFinished |= this.K.isFinished();
        }
        EdgeEffect edgeEffect3 = this.J;
        if (edgeEffect3 != null && !edgeEffect3.isFinished() && i2 > 0) {
            this.J.onRelease();
            zIsFinished |= this.J.isFinished();
        }
        EdgeEffect edgeEffect4 = this.L;
        if (edgeEffect4 != null && !edgeEffect4.isFinished() && i2 < 0) {
            this.L.onRelease();
            zIsFinished |= this.L.isFinished();
        }
        if (zIsFinished) {
            postInvalidateOnAnimation();
        }
    }

    public final void o0() {
        int i = this.v + 1;
        this.v = i;
        if (i != 1 || this.x) {
            return;
        }
        this.w = false;
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0058  */
    @Override // android.view.ViewGroup, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onAttachedToWindow() {
        /*
            r5 = this;
            super.onAttachedToWindow()
            r0 = 0
            r5.F = r0
            r1 = 1
            r5.s = r1
            boolean r2 = r5.u
            if (r2 == 0) goto L15
            boolean r2 = r5.isLayoutRequested()
            if (r2 != 0) goto L15
            r2 = r1
            goto L16
        L15:
            r2 = r0
        L16:
            r5.u = r2
            androidx.recyclerview.widget.v0 r2 = r5.c
            r2.d()
            androidx.recyclerview.widget.n0 r2 = r5.n
            if (r2 == 0) goto L26
            r2.g = r1
            r2.V(r5)
        L26:
            r5.x1 = r0
            boolean r0 = androidx.recyclerview.widget.RecyclerView.R1
            if (r0 == 0) goto L83
            java.lang.ThreadLocal r0 = androidx.recyclerview.widget.D.e
            java.lang.Object r1 = r0.get()
            androidx.recyclerview.widget.D r1 = (androidx.recyclerview.widget.D) r1
            r5.p1 = r1
            if (r1 != 0) goto L66
            androidx.recyclerview.widget.D r1 = new androidx.recyclerview.widget.D
            r1.<init>()
            r5.p1 = r1
            java.util.WeakHashMap r1 = androidx.core.view.V.a
            android.view.Display r1 = r5.getDisplay()
            boolean r2 = r5.isInEditMode()
            if (r2 != 0) goto L58
            if (r1 == 0) goto L58
            float r1 = r1.getRefreshRate()
            r2 = 1106247680(0x41f00000, float:30.0)
            int r2 = (r1 > r2 ? 1 : (r1 == r2 ? 0 : -1))
            if (r2 < 0) goto L58
            goto L5a
        L58:
            r1 = 1114636288(0x42700000, float:60.0)
        L5a:
            androidx.recyclerview.widget.D r2 = r5.p1
            r3 = 1315859240(0x4e6e6b28, float:1.0E9)
            float r3 = r3 / r1
            long r3 = (long) r3
            r2.c = r3
            r0.set(r2)
        L66:
            androidx.recyclerview.widget.D r0 = r5.p1
            r0.getClass()
            boolean r1 = androidx.recyclerview.widget.RecyclerView.M1
            java.util.ArrayList r0 = r0.a
            if (r1 == 0) goto L80
            boolean r1 = r0.contains(r5)
            if (r1 != 0) goto L78
            goto L80
        L78:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r1 = "RecyclerView already present in worker list!"
            r0.<init>(r1)
            throw r0
        L80:
            r0.add(r5)
        L83:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.RecyclerView.onAttachedToWindow():void");
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onDetachedFromWindow() {
        v0 v0Var;
        D d;
        super.onDetachedFromWindow();
        AbstractC1373j0 abstractC1373j0 = this.M;
        if (abstractC1373j0 != null) {
            abstractC1373j0.e();
        }
        s0();
        this.s = false;
        AbstractC1381n0 abstractC1381n0 = this.n;
        if (abstractC1381n0 != null) {
            abstractC1381n0.g = false;
            abstractC1381n0.W(this);
        }
        this.E1.clear();
        removeCallbacks(this.F1);
        this.g.getClass();
        while (Q0.d.a() != null) {
        }
        int i = 0;
        while (true) {
            v0Var = this.c;
            ArrayList arrayList = v0Var.c;
            if (i >= arrayList.size()) {
                break;
            }
            G6.b(((F0) arrayList.get(i)).itemView);
            i++;
        }
        v0Var.e(v0Var.h.m, false);
        Intrinsics.checkNotNullParameter(this, "<this>");
        Iterator it2 = new androidx.core.view.X(this).iterator();
        while (true) {
            androidx.core.view.Y y = (androidx.core.view.Y) it2;
            if (!y.hasNext()) {
                break;
            }
            ArrayList arrayList2 = G6.c((View) y.next()).a;
            for (int i2 = kotlin.collections.B.i(arrayList2); -1 < i2; i2--) {
                ((U0) arrayList2.get(i2)).a.disposeComposition();
            }
        }
        if (!R1 || (d = this.p1) == null) {
            return;
        }
        boolean zRemove = d.a.remove(this);
        if (M1 && !zRemove) {
            throw new IllegalStateException("RecyclerView removal failed!");
        }
        this.p1 = null;
    }

    @Override // android.view.View
    public final void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        ArrayList arrayList = this.p;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            ((AbstractC1375k0) arrayList.get(i)).onDraw(canvas, this, this.r1);
        }
    }

    @Override // android.view.View
    public final boolean onGenericMotionEvent(MotionEvent motionEvent) {
        float axisValue;
        int i;
        boolean z;
        if (this.n != null && !this.x && motionEvent.getAction() == 8) {
            int source = motionEvent.getSource() & 2;
            float axisValue2 = DefinitionKt.NO_Float_VALUE;
            if (source != 0) {
                float f = this.n.e() ? -motionEvent.getAxisValue(9) : 0.0f;
                if (this.n.d()) {
                    axisValue2 = motionEvent.getAxisValue(10);
                }
                axisValue = axisValue2;
                i = 0;
                z = false;
                axisValue2 = f;
            } else if ((motionEvent.getSource() & 4194304) != 0) {
                axisValue = motionEvent.getAxisValue(26);
                if (this.n.e()) {
                    float f2 = -axisValue;
                    axisValue = 0.0f;
                    axisValue2 = f2;
                } else if (!this.n.d()) {
                    axisValue = 0.0f;
                }
                i = 26;
                z = this.J1;
            } else {
                axisValue = 0.0f;
                i = 0;
                z = false;
            }
            int i2 = (int) (axisValue2 * this.m1);
            int i3 = (int) (axisValue * this.l1);
            if (z) {
                OverScroller overScroller = this.o1.c;
                m0((overScroller.getFinalX() - overScroller.getCurrX()) + i3, (overScroller.getFinalY() - overScroller.getCurrY()) + i2, true);
            } else {
                AbstractC1381n0 abstractC1381n0 = this.n;
                if (abstractC1381n0 == null) {
                    Log.e("RecyclerView", "Cannot scroll without a LayoutManager set. Call setLayoutManager with a non-null argument.");
                } else if (!this.x) {
                    int[] iArr = this.D1;
                    iArr[0] = 0;
                    iArr[1] = 0;
                    boolean zD = abstractC1381n0.d();
                    boolean zE = this.n.e();
                    int i4 = zE ? (zD ? 1 : 0) | 2 : zD ? 1 : 0;
                    float y = motionEvent.getY();
                    float x = motionEvent.getX();
                    int iE0 = i3 - e0(y, i3);
                    int iF0 = i2 - f0(x, i2);
                    getScrollingChildHelper().h(i4, 1);
                    if (w(zD ? iE0 : 0, zE ? iF0 : 0, 1, this.D1, this.B1)) {
                        iE0 -= iArr[0];
                        iF0 -= iArr[1];
                    }
                    i0(zD ? iE0 : 0, zE ? iF0 : 0, motionEvent, 1);
                    D d = this.p1;
                    if (d != null && (iE0 != 0 || iF0 != 0)) {
                        d.a(this, iE0, iF0);
                    }
                    r0(1);
                }
            }
            if (i != 0 && !z) {
                this.L1.a(motionEvent, i);
            }
        }
        return false;
    }

    @Override // android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent motionEvent) {
        boolean z;
        boolean z2;
        if (!this.x) {
            this.r = null;
            if (G(motionEvent)) {
                VelocityTracker velocityTracker = this.c1;
                if (velocityTracker != null) {
                    velocityTracker.clear();
                }
                r0(0);
                d0();
                setScrollState(0);
                return true;
            }
            AbstractC1381n0 abstractC1381n0 = this.n;
            if (abstractC1381n0 != null) {
                boolean zD = abstractC1381n0.d();
                boolean zE = this.n.e();
                if (this.c1 == null) {
                    this.c1 = VelocityTracker.obtain();
                }
                this.c1.addMovement(motionEvent);
                int actionMasked = motionEvent.getActionMasked();
                int actionIndex = motionEvent.getActionIndex();
                if (actionMasked == 0) {
                    if (this.y) {
                        this.y = false;
                    }
                    this.W = motionEvent.getPointerId(0);
                    int x = (int) (motionEvent.getX() + 0.5f);
                    this.f1 = x;
                    this.d1 = x;
                    int y = (int) (motionEvent.getY() + 0.5f);
                    this.g1 = y;
                    this.e1 = y;
                    EdgeEffect edgeEffect = this.I;
                    if (edgeEffect == null || androidx.core.widget.e.a(edgeEffect) == DefinitionKt.NO_Float_VALUE || canScrollHorizontally(-1)) {
                        z = false;
                    } else {
                        androidx.core.widget.e.b(this.I, DefinitionKt.NO_Float_VALUE, 1.0f - (motionEvent.getY() / getHeight()));
                        z = true;
                    }
                    EdgeEffect edgeEffect2 = this.K;
                    if (edgeEffect2 != null && androidx.core.widget.e.a(edgeEffect2) != DefinitionKt.NO_Float_VALUE && !canScrollHorizontally(1)) {
                        androidx.core.widget.e.b(this.K, DefinitionKt.NO_Float_VALUE, motionEvent.getY() / getHeight());
                        z = true;
                    }
                    EdgeEffect edgeEffect3 = this.J;
                    if (edgeEffect3 != null && androidx.core.widget.e.a(edgeEffect3) != DefinitionKt.NO_Float_VALUE && !canScrollVertically(-1)) {
                        androidx.core.widget.e.b(this.J, DefinitionKt.NO_Float_VALUE, motionEvent.getX() / getWidth());
                        z = true;
                    }
                    EdgeEffect edgeEffect4 = this.L;
                    if (edgeEffect4 != null && androidx.core.widget.e.a(edgeEffect4) != DefinitionKt.NO_Float_VALUE && !canScrollVertically(1)) {
                        androidx.core.widget.e.b(this.L, DefinitionKt.NO_Float_VALUE, 1.0f - (motionEvent.getX() / getWidth()));
                        z = true;
                    }
                    if (z || this.V == 2) {
                        getParent().requestDisallowInterceptTouchEvent(true);
                        setScrollState(1);
                        r0(1);
                    }
                    int[] iArr = this.C1;
                    iArr[1] = 0;
                    iArr[0] = 0;
                    p0(0);
                } else if (actionMasked == 1) {
                    this.c1.clear();
                    r0(0);
                } else if (actionMasked == 2) {
                    int iFindPointerIndex = motionEvent.findPointerIndex(this.W);
                    if (iFindPointerIndex < 0) {
                        Log.e("RecyclerView", "Error processing scroll; pointer index for id " + this.W + " not found. Did any MotionEvents get skipped?");
                        return false;
                    }
                    int x2 = (int) (motionEvent.getX(iFindPointerIndex) + 0.5f);
                    int y2 = (int) (motionEvent.getY(iFindPointerIndex) + 0.5f);
                    if (this.V != 1) {
                        int i = x2 - this.d1;
                        int i2 = y2 - this.e1;
                        if (!zD || Math.abs(i) <= this.h1) {
                            z2 = false;
                        } else {
                            this.f1 = x2;
                            z2 = true;
                        }
                        if (zE && Math.abs(i2) > this.h1) {
                            this.g1 = y2;
                            z2 = true;
                        }
                        if (z2) {
                            setScrollState(1);
                        }
                    }
                } else if (actionMasked == 3) {
                    VelocityTracker velocityTracker2 = this.c1;
                    if (velocityTracker2 != null) {
                        velocityTracker2.clear();
                    }
                    r0(0);
                    d0();
                    setScrollState(0);
                } else if (actionMasked == 5) {
                    this.W = motionEvent.getPointerId(actionIndex);
                    int x3 = (int) (motionEvent.getX(actionIndex) + 0.5f);
                    this.f1 = x3;
                    this.d1 = x3;
                    int y3 = (int) (motionEvent.getY(actionIndex) + 0.5f);
                    this.g1 = y3;
                    this.e1 = y3;
                } else if (actionMasked == 6) {
                    Y(motionEvent);
                }
                if (this.V == 1) {
                    return true;
                }
            }
        }
        return false;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onLayout(boolean z, int i, int i2, int i3, int i4) {
        Trace.beginSection("RV OnLayout");
        t();
        Trace.endSection();
        this.u = true;
    }

    @Override // android.view.View
    public final void onMeasure(int i, int i2) {
        AbstractC1381n0 abstractC1381n0 = this.n;
        if (abstractC1381n0 == null) {
            r(i, i2);
            return;
        }
        boolean zO = abstractC1381n0.O();
        boolean z = false;
        B0 b0 = this.r1;
        if (zO) {
            int mode = View.MeasureSpec.getMode(i);
            int mode2 = View.MeasureSpec.getMode(i2);
            this.n.b.r(i, i2);
            if (mode == 1073741824 && mode2 == 1073741824) {
                z = true;
            }
            this.G1 = z;
            if (z || this.m == null) {
                return;
            }
            if (b0.d == 1) {
                u();
            }
            this.n.y0(i, i2);
            b0.i = true;
            v();
            this.n.A0(i, i2);
            if (this.n.D0()) {
                this.n.y0(View.MeasureSpec.makeMeasureSpec(getMeasuredWidth(), 1073741824), View.MeasureSpec.makeMeasureSpec(getMeasuredHeight(), 1073741824));
                b0.i = true;
                v();
                this.n.A0(i, i2);
            }
            this.H1 = getMeasuredWidth();
            this.I1 = getMeasuredHeight();
            return;
        }
        if (this.t) {
            this.n.b.r(i, i2);
            return;
        }
        if (this.A) {
            o0();
            W();
            a0();
            X(true);
            if (b0.k) {
                b0.g = true;
            } else {
                this.e.d();
                b0.g = false;
            }
            this.A = false;
            q0(false);
        } else if (b0.k) {
            setMeasuredDimension(getMeasuredWidth(), getMeasuredHeight());
            return;
        }
        AbstractC1361d0 abstractC1361d0 = this.m;
        if (abstractC1361d0 != null) {
            b0.e = abstractC1361d0.getItemCount();
        } else {
            b0.e = 0;
        }
        o0();
        this.n.b.r(i, i2);
        q0(false);
        b0.g = false;
    }

    @Override // android.view.ViewGroup
    public final boolean onRequestFocusInDescendants(int i, Rect rect) {
        if (S()) {
            return false;
        }
        return super.onRequestFocusInDescendants(i, rect);
    }

    @Override // android.view.View
    public final void onRestoreInstanceState(Parcelable parcelable) {
        if (!(parcelable instanceof SavedState)) {
            super.onRestoreInstanceState(parcelable);
            return;
        }
        SavedState savedState = (SavedState) parcelable;
        this.d = savedState;
        super.onRestoreInstanceState(savedState.a);
        requestLayout();
    }

    @Override // android.view.View
    public final Parcelable onSaveInstanceState() {
        SavedState savedState = new SavedState(super.onSaveInstanceState());
        SavedState savedState2 = this.d;
        if (savedState2 != null) {
            savedState.c = savedState2.c;
            return savedState;
        }
        AbstractC1381n0 abstractC1381n0 = this.n;
        if (abstractC1381n0 != null) {
            savedState.c = abstractC1381n0.k0();
            return savedState;
        }
        savedState.c = null;
        return savedState;
    }

    @Override // android.view.View
    public final void onSizeChanged(int i, int i2, int i3, int i4) {
        super.onSizeChanged(i, i2, i3, i4);
        if (i == i3 && i2 == i4) {
            return;
        }
        this.L = null;
        this.J = null;
        this.K = null;
        this.I = null;
    }

    /* JADX WARN: Removed duplicated region for block: B:62:0x0111 A[PHI: r1
  0x0111: PHI (r1v47 int) = (r1v31 int), (r1v51 int) binds: [B:56:0x00fa, B:60:0x010d] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:64:0x0114  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x012a  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean onTouchEvent(android.view.MotionEvent r19) {
        /*
            Method dump skipped, instructions count: 548
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.RecyclerView.onTouchEvent(android.view.MotionEvent):boolean");
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void p0(int i) {
        boolean zD = this.n.d();
        int i2 = zD;
        if (this.n.e()) {
            i2 = (zD ? 1 : 0) | 2;
        }
        getScrollingChildHelper().h(i2, i);
    }

    public final void q() {
        if (!this.u || this.D) {
            Trace.beginSection("RV FullInvalidate");
            t();
            Trace.endSection();
            return;
        }
        if (this.e.h()) {
            androidx.navigation.internal.m mVar = this.e;
            int i = mVar.c;
            if ((i & 4) == 0 || (i & 11) != 0) {
                if (mVar.h()) {
                    Trace.beginSection("RV FullInvalidate");
                    t();
                    Trace.endSection();
                    return;
                }
                return;
            }
            Trace.beginSection("RV PartialInvalidate");
            o0();
            W();
            this.e.l();
            if (!this.w) {
                int iX = this.f.x();
                int i2 = 0;
                while (true) {
                    if (i2 < iX) {
                        F0 f0P = P(this.f.w(i2));
                        if (f0P != null && !f0P.shouldIgnore() && f0P.isUpdated()) {
                            t();
                            break;
                        }
                        i2++;
                    } else {
                        this.e.c();
                        break;
                    }
                }
            }
            q0(true);
            X(true);
            Trace.endSection();
        }
    }

    public final void q0(boolean z) {
        if (this.v < 1) {
            if (M1) {
                throw new IllegalStateException(androidx.compose.ui.node.B.c(this, new StringBuilder("stopInterceptRequestLayout was called more times than startInterceptRequestLayout.")));
            }
            this.v = 1;
        }
        if (!z && !this.x) {
            this.w = false;
        }
        if (this.v == 1) {
            if (z && this.w && !this.x && this.n != null && this.m != null) {
                t();
            }
            if (!this.x) {
                this.w = false;
            }
        }
        this.v--;
    }

    public final void r(int i, int i2) {
        int paddingRight = getPaddingRight() + getPaddingLeft();
        WeakHashMap weakHashMap = androidx.core.view.V.a;
        setMeasuredDimension(AbstractC1381n0.g(i, paddingRight, getMinimumWidth()), AbstractC1381n0.g(i2, getPaddingBottom() + getPaddingTop(), getMinimumHeight()));
    }

    public final void r0(int i) {
        getScrollingChildHelper().i(i);
    }

    @Override // android.view.ViewGroup
    public final void removeDetachedView(View view, boolean z) {
        F0 f0P = P(view);
        if (f0P != null) {
            if (f0P.isTmpDetached()) {
                f0P.clearTmpDetachFlag();
            } else if (!f0P.shouldIgnore()) {
                StringBuilder sb = new StringBuilder("Called removeDetachedView with a view which is not flagged as tmp detached.");
                sb.append(f0P);
                throw new IllegalArgumentException(androidx.compose.ui.node.B.c(this, sb));
            }
        } else if (M1) {
            StringBuilder sb2 = new StringBuilder("No ViewHolder found for child: ");
            sb2.append(view);
            throw new IllegalArgumentException(androidx.compose.ui.node.B.c(this, sb2));
        }
        view.clearAnimation();
        s(view);
        super.removeDetachedView(view, z);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final void requestChildFocus(View view, View view2) {
        S s = this.n.e;
        if ((s == null || !s.e) && !S() && view2 != null) {
            h0(view, view2);
        }
        super.requestChildFocus(view, view2);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final boolean requestChildRectangleOnScreen(View view, Rect rect, boolean z) {
        return this.n.s0(this, view, rect, z, false);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final void requestDisallowInterceptTouchEvent(boolean z) {
        ArrayList arrayList = this.q;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            ((InterfaceC1388r0) arrayList.get(i)).e(z);
        }
        super.requestDisallowInterceptTouchEvent(z);
    }

    @Override // android.view.View, android.view.ViewParent
    public final void requestLayout() {
        if (this.v != 0 || this.x) {
            this.w = true;
        } else {
            super.requestLayout();
        }
    }

    public final void s(View view) {
        F0 f0P = P(view);
        AbstractC1361d0 abstractC1361d0 = this.m;
        if (abstractC1361d0 != null && f0P != null) {
            abstractC1361d0.onViewDetachedFromWindow(f0P);
        }
        ArrayList arrayList = this.C;
        if (arrayList != null) {
            for (int size = arrayList.size() - 1; size >= 0; size--) {
                ((InterfaceC1385p0) this.C.get(size)).b(view);
            }
        }
    }

    public final void s0() {
        S s;
        setScrollState(0);
        E0 e0 = this.o1;
        e0.g.removeCallbacks(e0);
        e0.c.abortAnimation();
        AbstractC1381n0 abstractC1381n0 = this.n;
        if (abstractC1381n0 == null || (s = abstractC1381n0.e) == null) {
            return;
        }
        s.k();
    }

    @Override // android.view.View
    public final void scrollBy(int i, int i2) {
        AbstractC1381n0 abstractC1381n0 = this.n;
        if (abstractC1381n0 == null) {
            Log.e("RecyclerView", "Cannot scroll without a LayoutManager set. Call setLayoutManager with a non-null argument.");
            return;
        }
        if (this.x) {
            return;
        }
        boolean zD = abstractC1381n0.d();
        boolean zE = this.n.e();
        if (zD || zE) {
            if (!zD) {
                i = 0;
            }
            if (!zE) {
                i2 = 0;
            }
            i0(i, i2, null, 0);
        }
    }

    @Override // android.view.View
    public final void scrollTo(int i, int i2) {
        Log.w("RecyclerView", "RecyclerView does not support scrolling to an absolute position. Use scrollToPosition instead");
    }

    @Override // android.view.View, android.view.accessibility.AccessibilityEventSource
    public final void sendAccessibilityEventUnchecked(AccessibilityEvent accessibilityEvent) {
        if (!S()) {
            super.sendAccessibilityEventUnchecked(accessibilityEvent);
        } else {
            int contentChangeTypes = accessibilityEvent != null ? accessibilityEvent.getContentChangeTypes() : 0;
            this.z |= contentChangeTypes != 0 ? contentChangeTypes : 0;
        }
    }

    public void setAccessibilityDelegateCompat(H0 h0) {
        this.y1 = h0;
        androidx.core.view.V.o(this, h0);
    }

    public void setAdapter(AbstractC1361d0 abstractC1361d0) {
        setLayoutFrozen(false);
        AbstractC1361d0 abstractC1361d02 = this.m;
        x0 x0Var = this.b;
        if (abstractC1361d02 != null) {
            abstractC1361d02.unregisterAdapterDataObserver(x0Var);
            this.m.onDetachedFromRecyclerView(this);
        }
        AbstractC1373j0 abstractC1373j0 = this.M;
        if (abstractC1373j0 != null) {
            abstractC1373j0.e();
        }
        AbstractC1381n0 abstractC1381n0 = this.n;
        v0 v0Var = this.c;
        if (abstractC1381n0 != null) {
            abstractC1381n0.o0(v0Var);
            this.n.p0(v0Var);
        }
        v0Var.a.clear();
        v0Var.f();
        androidx.navigation.internal.m mVar = this.e;
        mVar.m((ArrayList) mVar.b);
        mVar.m((ArrayList) mVar.e);
        mVar.c = 0;
        AbstractC1361d0 abstractC1361d03 = this.m;
        this.m = abstractC1361d0;
        if (abstractC1361d0 != null) {
            abstractC1361d0.registerAdapterDataObserver(x0Var);
            abstractC1361d0.onAttachedToRecyclerView(this);
        }
        AbstractC1381n0 abstractC1381n02 = this.n;
        if (abstractC1381n02 != null) {
            abstractC1381n02.U();
        }
        AbstractC1361d0 abstractC1361d04 = this.m;
        v0Var.a.clear();
        v0Var.f();
        v0Var.e(abstractC1361d03, true);
        u0 u0VarC = v0Var.c();
        if (abstractC1361d03 != null) {
            u0VarC.b--;
        }
        if (u0VarC.b == 0) {
            int i = 0;
            while (true) {
                SparseArray sparseArray = u0VarC.a;
                if (i >= sparseArray.size()) {
                    break;
                }
                t0 t0Var = (t0) sparseArray.valueAt(i);
                Iterator it2 = t0Var.a.iterator();
                while (it2.hasNext()) {
                    G6.b(((F0) it2.next()).itemView);
                }
                t0Var.a.clear();
                i++;
            }
        }
        if (abstractC1361d04 != null) {
            u0VarC.b++;
        }
        v0Var.d();
        this.r1.f = true;
        b0(false);
        requestLayout();
    }

    public void setChildDrawingOrderCallback(InterfaceC1369h0 interfaceC1369h0) {
        if (interfaceC1369h0 == null) {
            return;
        }
        setChildrenDrawingOrderEnabled(interfaceC1369h0 != null);
    }

    @Override // android.view.ViewGroup
    public void setClipToPadding(boolean z) {
        if (z != this.h) {
            this.L = null;
            this.J = null;
            this.K = null;
            this.I = null;
        }
        this.h = z;
        super.setClipToPadding(z);
        if (this.u) {
            requestLayout();
        }
    }

    public void setEdgeEffectFactory(@NonNull AbstractC1371i0 abstractC1371i0) {
        abstractC1371i0.getClass();
        this.H = abstractC1371i0;
        this.L = null;
        this.J = null;
        this.K = null;
        this.I = null;
    }

    public void setHasFixedSize(boolean z) {
        this.t = z;
    }

    public void setItemAnimator(AbstractC1373j0 abstractC1373j0) {
        AbstractC1373j0 abstractC1373j02 = this.M;
        if (abstractC1373j02 != null) {
            abstractC1373j02.e();
            this.M.a = null;
        }
        this.M = abstractC1373j0;
        if (abstractC1373j0 != null) {
            abstractC1373j0.a = this.w1;
        }
    }

    public void setItemViewCacheSize(int i) {
        v0 v0Var = this.c;
        v0Var.e = i;
        v0Var.m();
    }

    @Deprecated
    public void setLayoutFrozen(boolean z) {
        suppressLayout(z);
    }

    public void setLayoutManager(AbstractC1381n0 abstractC1381n0) {
        RecyclerView recyclerView;
        if (abstractC1381n0 == this.n) {
            return;
        }
        s0();
        AbstractC1381n0 abstractC1381n02 = this.n;
        v0 v0Var = this.c;
        if (abstractC1381n02 != null) {
            AbstractC1373j0 abstractC1373j0 = this.M;
            if (abstractC1373j0 != null) {
                abstractC1373j0.e();
            }
            this.n.o0(v0Var);
            this.n.p0(v0Var);
            v0Var.a.clear();
            v0Var.f();
            if (this.s) {
                AbstractC1381n0 abstractC1381n03 = this.n;
                abstractC1381n03.g = false;
                abstractC1381n03.W(this);
            }
            this.n.B0(null);
            this.n = null;
        } else {
            v0Var.a.clear();
            v0Var.f();
        }
        androidx.camera.camera2.internal.concurrent.a aVar = this.f;
        ((l1) aVar.e).G();
        ArrayList arrayList = (ArrayList) aVar.c;
        int size = arrayList.size() - 1;
        while (true) {
            recyclerView = ((C1357b0) aVar.d).a;
            if (size < 0) {
                break;
            }
            F0 f0P = P((View) arrayList.get(size));
            if (f0P != null) {
                f0P.onLeftHiddenState(recyclerView);
            }
            arrayList.remove(size);
            size--;
        }
        int childCount = recyclerView.getChildCount();
        for (int i = 0; i < childCount; i++) {
            View childAt = recyclerView.getChildAt(i);
            recyclerView.s(childAt);
            childAt.clearAnimation();
        }
        recyclerView.removeAllViews();
        this.n = abstractC1381n0;
        if (abstractC1381n0 != null) {
            if (abstractC1381n0.b != null) {
                StringBuilder sb = new StringBuilder("LayoutManager ");
                sb.append(abstractC1381n0);
                sb.append(" is already attached to a RecyclerView:");
                throw new IllegalArgumentException(androidx.compose.ui.node.B.c(abstractC1381n0.b, sb));
            }
            abstractC1381n0.B0(this);
            if (this.s) {
                AbstractC1381n0 abstractC1381n04 = this.n;
                abstractC1381n04.g = true;
                abstractC1381n04.V(this);
            }
        }
        v0Var.m();
        requestLayout();
    }

    @Override // android.view.ViewGroup
    @Deprecated
    public void setLayoutTransition(LayoutTransition layoutTransition) {
        if (layoutTransition != null) {
            throw new IllegalArgumentException("Providing a LayoutTransition into RecyclerView is not supported. Please use setItemAnimator() instead for animating changes to the items in this RecyclerView");
        }
        super.setLayoutTransition(null);
    }

    @Override // android.view.View
    public void setNestedScrollingEnabled(boolean z) {
        getScrollingChildHelper().g(z);
    }

    public void setOnFlingListener(AbstractC1387q0 abstractC1387q0) {
        this.i1 = abstractC1387q0;
    }

    @Deprecated
    public void setOnScrollListener(AbstractC1390s0 abstractC1390s0) {
        this.s1 = abstractC1390s0;
    }

    public void setPreserveFocusAfterLayout(boolean z) {
        this.n1 = z;
    }

    public void setRecycledViewPool(u0 u0Var) {
        v0 v0Var = this.c;
        RecyclerView recyclerView = v0Var.h;
        v0Var.e(recyclerView.m, false);
        if (v0Var.g != null) {
            r2.b--;
        }
        v0Var.g = u0Var;
        if (u0Var != null && recyclerView.getAdapter() != null) {
            v0Var.g.b++;
        }
        v0Var.d();
    }

    @Deprecated
    public void setRecyclerListener(w0 w0Var) {
    }

    public void setScrollState(int i) {
        S s;
        if (i == this.V) {
            return;
        }
        if (N1) {
            new Exception();
        }
        this.V = i;
        if (i != 2) {
            E0 e0 = this.o1;
            e0.g.removeCallbacks(e0);
            e0.c.abortAnimation();
            AbstractC1381n0 abstractC1381n0 = this.n;
            if (abstractC1381n0 != null && (s = abstractC1381n0.e) != null) {
                s.k();
            }
        }
        AbstractC1381n0 abstractC1381n02 = this.n;
        if (abstractC1381n02 != null) {
            abstractC1381n02.l0(i);
        }
        AbstractC1390s0 abstractC1390s0 = this.s1;
        if (abstractC1390s0 != null) {
            abstractC1390s0.a(this, i);
        }
        ArrayList arrayList = this.t1;
        if (arrayList != null) {
            for (int size = arrayList.size() - 1; size >= 0; size--) {
                ((AbstractC1390s0) this.t1.get(size)).a(this, i);
            }
        }
    }

    public void setScrollingTouchSlop(int i) {
        ViewConfiguration viewConfiguration = ViewConfiguration.get(getContext());
        if (i != 0) {
            if (i == 1) {
                this.h1 = viewConfiguration.getScaledPagingTouchSlop();
                return;
            }
            Log.w("RecyclerView", "setScrollingTouchSlop(): bad argument constant " + i + "; using default value");
        }
        this.h1 = viewConfiguration.getScaledTouchSlop();
    }

    public void setViewCacheExtension(D0 d0) {
        this.c.getClass();
    }

    @Override // android.view.View
    public final boolean startNestedScroll(int i) {
        return getScrollingChildHelper().h(i, 0);
    }

    @Override // android.view.View
    public final void stopNestedScroll() {
        getScrollingChildHelper().i(0);
    }

    @Override // android.view.ViewGroup
    public final void suppressLayout(boolean z) {
        if (z != this.x) {
            l("Do not suppressLayout in layout or scroll");
            if (z) {
                long jUptimeMillis = SystemClock.uptimeMillis();
                onTouchEvent(MotionEvent.obtain(jUptimeMillis, jUptimeMillis, 3, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 0));
                this.x = true;
                this.y = true;
                s0();
                return;
            }
            this.x = false;
            if (this.w && this.n != null && this.m != null) {
                requestLayout();
            }
            this.w = false;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:166:0x034e  */
    /* JADX WARN: Removed duplicated region for block: B:188:0x03a2  */
    /* JADX WARN: Removed duplicated region for block: B:190:0x03a5  */
    /* JADX WARN: Removed duplicated region for block: B:196:0x03bf  */
    /* JADX WARN: Type inference failed for: r3v11 */
    /* JADX WARN: Type inference failed for: r3v18 */
    /* JADX WARN: Type inference failed for: r3v19, types: [int] */
    /* JADX WARN: Type inference failed for: r3v22 */
    /* JADX WARN: Type inference failed for: r3v25 */
    /* JADX WARN: Type inference failed for: r3v26 */
    /* JADX WARN: Type inference failed for: r3v27 */
    /* JADX WARN: Type inference failed for: r3v28 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void t() {
        /*
            Method dump skipped, instructions count: 1063
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.RecyclerView.t():void");
    }

    public final void u() {
        Q0 q0;
        View viewF;
        B0 b0 = this.r1;
        b0.a(1);
        E(b0);
        b0.i = false;
        o0();
        N0 n0 = this.g;
        ((androidx.collection.V) n0.a).clear();
        C0219q c0219q = (C0219q) n0.b;
        c0219q.b();
        W();
        a0();
        F0 f0O = null;
        View focusedChild = (this.n1 && hasFocus() && this.m != null) ? getFocusedChild() : null;
        if (focusedChild != null && (viewF = F(focusedChild)) != null) {
            f0O = O(viewF);
        }
        if (f0O == null) {
            b0.m = -1L;
            b0.l = -1;
            b0.n = -1;
        } else {
            b0.m = this.m.hasStableIds() ? f0O.getItemId() : -1L;
            b0.l = this.D ? -1 : f0O.isRemoved() ? f0O.mOldPosition : f0O.getAbsoluteAdapterPosition();
            View focusedChild2 = f0O.itemView;
            int id = focusedChild2.getId();
            while (!focusedChild2.isFocused() && (focusedChild2 instanceof ViewGroup) && focusedChild2.hasFocus()) {
                focusedChild2 = ((ViewGroup) focusedChild2).getFocusedChild();
                if (focusedChild2.getId() != -1) {
                    id = focusedChild2.getId();
                }
            }
            b0.n = id;
        }
        b0.h = b0.j && this.v1;
        this.v1 = false;
        this.u1 = false;
        b0.g = b0.k;
        b0.e = this.m.getItemCount();
        H(this.z1);
        boolean z = b0.j;
        androidx.collection.V v = (androidx.collection.V) n0.a;
        if (z) {
            int iX = this.f.x();
            for (int i = 0; i < iX; i++) {
                F0 f0P = P(this.f.w(i));
                if (!f0P.shouldIgnore() && (!f0P.isInvalid() || this.m.hasStableIds())) {
                    AbstractC1373j0 abstractC1373j0 = this.M;
                    AbstractC1373j0.b(f0P);
                    f0P.getUnmodifiedPayloads();
                    abstractC1373j0.getClass();
                    C0676l1 c0676l1 = new C0676l1();
                    c0676l1.b(f0P);
                    Q0 q0A = (Q0) v.get(f0P);
                    if (q0A == null) {
                        q0A = Q0.a();
                        v.put(f0P, q0A);
                    }
                    q0A.b = c0676l1;
                    q0A.a |= 4;
                    if (b0.h && f0P.isUpdated() && !f0P.isRemoved() && !f0P.shouldIgnore() && !f0P.isInvalid()) {
                        c0219q.g(N(f0P), f0P);
                    }
                }
            }
        }
        if (b0.k) {
            int iC = this.f.C();
            for (int i2 = 0; i2 < iC; i2++) {
                F0 f0P2 = P(this.f.B(i2));
                if (M1 && f0P2.mPosition == -1 && !f0P2.isRemoved()) {
                    throw new IllegalStateException(androidx.compose.ui.node.B.c(this, new StringBuilder("view holder cannot have position -1 unless it is removed")));
                }
                if (!f0P2.shouldIgnore()) {
                    f0P2.saveOldPosition();
                }
            }
            boolean z2 = b0.f;
            b0.f = false;
            this.n.h0(this.c, b0);
            b0.f = z2;
            for (int i3 = 0; i3 < this.f.x(); i3++) {
                F0 f0P3 = P(this.f.w(i3));
                if (!f0P3.shouldIgnore() && ((q0 = (Q0) v.get(f0P3)) == null || (q0.a & 4) == 0)) {
                    AbstractC1373j0.b(f0P3);
                    boolean zHasAnyOfTheFlags = f0P3.hasAnyOfTheFlags(8192);
                    AbstractC1373j0 abstractC1373j02 = this.M;
                    f0P3.getUnmodifiedPayloads();
                    abstractC1373j02.getClass();
                    C0676l1 c0676l12 = new C0676l1();
                    c0676l12.b(f0P3);
                    if (zHasAnyOfTheFlags) {
                        c0(f0P3, c0676l12);
                    } else {
                        Q0 q0A2 = (Q0) v.get(f0P3);
                        if (q0A2 == null) {
                            q0A2 = Q0.a();
                            v.put(f0P3, q0A2);
                        }
                        q0A2.a |= 2;
                        q0A2.b = c0676l12;
                    }
                }
            }
            n();
        } else {
            n();
        }
        X(true);
        q0(false);
        b0.d = 2;
    }

    public final void v() {
        o0();
        W();
        B0 b0 = this.r1;
        b0.a(6);
        this.e.d();
        b0.e = this.m.getItemCount();
        b0.c = 0;
        if (this.d != null && this.m.canRestoreState()) {
            Parcelable parcelable = this.d.c;
            if (parcelable != null) {
                this.n.j0(parcelable);
            }
            this.d = null;
        }
        b0.g = false;
        this.n.h0(this.c, b0);
        b0.f = false;
        b0.j = b0.j && this.M != null;
        b0.d = 4;
        X(true);
        q0(false);
    }

    public final boolean w(int i, int i2, int i3, int[] iArr, int[] iArr2) {
        return getScrollingChildHelper().c(i, i2, i3, iArr, iArr2);
    }

    public final void x(int i, int i2, int i3, int i4, int[] iArr, int i5, int[] iArr2) {
        getScrollingChildHelper().d(i, i2, i3, i4, iArr, i5, iArr2);
    }

    public final void y(int i, int i2) {
        this.G++;
        int scrollX = getScrollX();
        int scrollY = getScrollY();
        onScrollChanged(scrollX, scrollY, scrollX - i, scrollY - i2);
        AbstractC1390s0 abstractC1390s0 = this.s1;
        if (abstractC1390s0 != null) {
            abstractC1390s0.b(this, i, i2);
        }
        ArrayList arrayList = this.t1;
        if (arrayList != null) {
            for (int size = arrayList.size() - 1; size >= 0; size--) {
                ((AbstractC1390s0) this.t1.get(size)).b(this, i, i2);
            }
        }
        this.G--;
    }

    public final void z() {
        if (this.L != null) {
            return;
        }
        ((C0) this.H).getClass();
        EdgeEffect edgeEffect = new EdgeEffect(getContext());
        this.L = edgeEffect;
        if (this.h) {
            edgeEffect.setSize((getMeasuredWidth() - getPaddingLeft()) - getPaddingRight(), (getMeasuredHeight() - getPaddingTop()) - getPaddingBottom());
        } else {
            edgeEffect.setSize(getMeasuredWidth(), getMeasuredHeight());
        }
    }

    public RecyclerView(@NonNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, com.quizlet.quizletandroid.R.attr.recyclerViewStyle);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r19v0 */
    /* JADX WARN: Type inference failed for: r19v1 */
    /* JADX WARN: Type inference failed for: r19v2 */
    public RecyclerView(Context context, AttributeSet attributeSet, int i) throws NoSuchMethodException, SecurityException {
        char c;
        boolean z;
        char c2;
        int i2;
        TypedArray typedArray;
        ClassLoader classLoader;
        Constructor constructor;
        super(context, attributeSet, i);
        int i3 = 1;
        this.b = new x0(this);
        this.c = new v0(this);
        this.g = new N0(4);
        this.i = new RunnableC1355a0(this, 0);
        this.j = new Rect();
        this.k = new Rect();
        this.l = new RectF();
        this.o = new ArrayList();
        this.p = new ArrayList();
        this.q = new ArrayList();
        this.v = 0;
        this.D = false;
        this.E = false;
        this.F = 0;
        this.G = 0;
        this.H = U1;
        C1386q c1386q = new C1386q();
        Object[] objArr = null;
        c1386q.a = null;
        c1386q.b = new ArrayList();
        c1386q.c = 120L;
        c1386q.d = 120L;
        c1386q.e = 250L;
        c1386q.f = 250L;
        c1386q.g = true;
        c1386q.h = new ArrayList();
        c1386q.i = new ArrayList();
        c1386q.j = new ArrayList();
        c1386q.k = new ArrayList();
        c1386q.l = new ArrayList();
        c1386q.m = new ArrayList();
        c1386q.n = new ArrayList();
        c1386q.o = new ArrayList();
        c1386q.p = new ArrayList();
        c1386q.q = new ArrayList();
        c1386q.r = new ArrayList();
        this.M = c1386q;
        this.V = 0;
        this.W = -1;
        this.l1 = Float.MIN_VALUE;
        this.m1 = Float.MIN_VALUE;
        this.n1 = true;
        this.o1 = new E0(this);
        this.q1 = R1 ? new C0210h() : null;
        B0 b0 = new B0();
        b0.a = -1;
        b0.b = 0;
        b0.c = 0;
        b0.d = 1;
        b0.e = 0;
        b0.f = false;
        b0.g = false;
        b0.h = false;
        b0.i = false;
        b0.j = false;
        b0.k = false;
        this.r1 = b0;
        this.u1 = false;
        this.v1 = false;
        C1357b0 c1357b0 = new C1357b0(this);
        this.w1 = c1357b0;
        this.x1 = false;
        this.z1 = new int[2];
        this.B1 = new int[2];
        this.C1 = new int[2];
        this.D1 = new int[2];
        this.E1 = new ArrayList();
        this.F1 = new RunnableC1355a0(this, i3);
        this.H1 = 0;
        this.I1 = 0;
        this.K1 = new C1357b0(this);
        this.L1 = new C1052i(getContext(), new C1357b0(this));
        setScrollContainer(true);
        setFocusableInTouchMode(true);
        ViewConfiguration viewConfiguration = ViewConfiguration.get(context);
        this.h1 = viewConfiguration.getScaledTouchSlop();
        this.l1 = viewConfiguration.getScaledHorizontalScrollFactor();
        this.m1 = viewConfiguration.getScaledVerticalScrollFactor();
        this.j1 = viewConfiguration.getScaledMinimumFlingVelocity();
        this.k1 = viewConfiguration.getScaledMaximumFlingVelocity();
        this.a = context.getResources().getDisplayMetrics().density * 160.0f * 386.0878f * 0.84f;
        setWillNotDraw(getOverScrollMode() == 2);
        this.M.a = c1357b0;
        this.e = new androidx.navigation.internal.m(new C1357b0(this));
        this.f = new androidx.camera.camera2.internal.concurrent.a(new C1357b0(this));
        WeakHashMap weakHashMap = androidx.core.view.V.a;
        if (androidx.core.view.O.a(this) == 0) {
            androidx.core.view.O.b(this, 8);
        }
        if (getImportantForAccessibility() == 0) {
            setImportantForAccessibility(1);
        }
        this.B = (AccessibilityManager) getContext().getSystemService("accessibility");
        setAccessibilityDelegateCompat(new H0(this));
        int[] iArr = androidx.recyclerview.a.a;
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, iArr, i, 0);
        androidx.core.view.V.n(this, context, iArr, attributeSet, typedArrayObtainStyledAttributes, i);
        String string = typedArrayObtainStyledAttributes.getString(8);
        if (typedArrayObtainStyledAttributes.getInt(2, -1) == -1) {
            setDescendantFocusability(262144);
        }
        this.h = typedArrayObtainStyledAttributes.getBoolean(1, true);
        if (typedArrayObtainStyledAttributes.getBoolean(3, false)) {
            StateListDrawable stateListDrawable = (StateListDrawable) typedArrayObtainStyledAttributes.getDrawable(6);
            Drawable drawable = typedArrayObtainStyledAttributes.getDrawable(7);
            StateListDrawable stateListDrawable2 = (StateListDrawable) typedArrayObtainStyledAttributes.getDrawable(4);
            Drawable drawable2 = typedArrayObtainStyledAttributes.getDrawable(5);
            if (stateListDrawable != null && drawable != null && stateListDrawable2 != null && drawable2 != null) {
                Resources resources = getContext().getResources();
                c2 = 2;
                z = 1;
                typedArray = typedArrayObtainStyledAttributes;
                i2 = i;
                c = 3;
                new B(this, stateListDrawable, drawable, stateListDrawable2, drawable2, resources.getDimensionPixelSize(com.quizlet.quizletandroid.R.dimen.fastscroll_default_thickness), resources.getDimensionPixelSize(com.quizlet.quizletandroid.R.dimen.fastscroll_minimum_range), resources.getDimensionPixelOffset(com.quizlet.quizletandroid.R.dimen.fastscroll_margin));
            } else {
                throw new IllegalArgumentException(androidx.compose.ui.node.B.c(this, new StringBuilder("Trying to set fast scroller without both required drawables.")));
            }
        } else {
            c = 3;
            z = 1;
            c2 = 2;
            i2 = i;
            typedArray = typedArrayObtainStyledAttributes;
        }
        typedArray.recycle();
        this.J1 = context.getPackageManager().hasSystemFeature("android.hardware.rotaryencoder.lowres");
        if (string != null) {
            String strTrim = string.trim();
            if (!strTrim.isEmpty()) {
                if (strTrim.charAt(0) == '.') {
                    strTrim = context.getPackageName() + strTrim;
                } else if (!strTrim.contains(".")) {
                    strTrim = RecyclerView.class.getPackage().getName() + '.' + strTrim;
                }
                String str = strTrim;
                try {
                    if (isInEditMode()) {
                        classLoader = getClass().getClassLoader();
                    } else {
                        classLoader = context.getClassLoader();
                    }
                    Class clsAsSubclass = Class.forName(str, false, classLoader).asSubclass(AbstractC1381n0.class);
                    try {
                        constructor = clsAsSubclass.getConstructor(S1);
                        Object[] objArr2 = new Object[4];
                        objArr2[0] = context;
                        objArr2[z] = attributeSet;
                        objArr2[c2] = Integer.valueOf(i2);
                        objArr2[c] = 0;
                        objArr = objArr2;
                    } catch (NoSuchMethodException e) {
                        try {
                            constructor = clsAsSubclass.getConstructor(null);
                        } catch (NoSuchMethodException e2) {
                            e2.initCause(e);
                            throw new IllegalStateException(attributeSet.getPositionDescription() + ": Error creating LayoutManager " + str, e2);
                        }
                    }
                    constructor.setAccessible(z);
                    setLayoutManager((AbstractC1381n0) constructor.newInstance(objArr));
                } catch (ClassCastException e3) {
                    throw new IllegalStateException(attributeSet.getPositionDescription() + ": Class is not a LayoutManager " + str, e3);
                } catch (ClassNotFoundException e4) {
                    throw new IllegalStateException(attributeSet.getPositionDescription() + ": Unable to find LayoutManager " + str, e4);
                } catch (IllegalAccessException e5) {
                    throw new IllegalStateException(attributeSet.getPositionDescription() + ": Cannot access non-public constructor " + str, e5);
                } catch (InstantiationException e6) {
                    throw new IllegalStateException(attributeSet.getPositionDescription() + ": Could not instantiate the LayoutManager: " + str, e6);
                } catch (InvocationTargetException e7) {
                    throw new IllegalStateException(attributeSet.getPositionDescription() + ": Could not instantiate the LayoutManager: " + str, e7);
                }
            }
        }
        int[] iArr2 = O1;
        TypedArray typedArrayObtainStyledAttributes2 = context.obtainStyledAttributes(attributeSet, iArr2, i2, 0);
        androidx.core.view.V.n(this, context, iArr2, attributeSet, typedArrayObtainStyledAttributes2, i2);
        boolean z2 = typedArrayObtainStyledAttributes2.getBoolean(0, true);
        typedArrayObtainStyledAttributes2.recycle();
        setNestedScrollingEnabled(z2);
        Intrinsics.checkNotNullParameter(this, "<this>");
        setTag(com.quizlet.quizletandroid.R.id.is_pooling_container_tag, Boolean.TRUE);
    }

    @Override // android.view.ViewGroup
    public final ViewGroup.LayoutParams generateLayoutParams(ViewGroup.LayoutParams layoutParams) {
        AbstractC1381n0 abstractC1381n0 = this.n;
        if (abstractC1381n0 != null) {
            return abstractC1381n0.t(layoutParams);
        }
        throw new IllegalStateException(androidx.compose.ui.node.B.c(this, new StringBuilder("RecyclerView has no LayoutManager")));
    }
}
