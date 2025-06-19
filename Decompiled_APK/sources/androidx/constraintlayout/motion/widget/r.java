package androidx.constraintlayout.motion.widget;

import android.content.Context;
import android.graphics.Matrix;
import android.graphics.Rect;
import android.graphics.RectF;
import android.os.Bundle;
import android.util.Log;
import android.util.SparseArray;
import android.view.Display;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.AnimationUtils;
import android.view.animation.BounceInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.Interpolator;
import android.view.animation.OvershootInterpolator;
import androidx.annotation.NonNull;
import androidx.appcompat.app.J;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.core.view.InterfaceC1061s;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3134e6;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArrayList;

/* loaded from: classes.dex */
public class r extends ConstraintLayout implements InterfaceC1061s {
    public static boolean J1;
    public long A;
    public final Rect A1;
    public float B;
    public boolean B1;
    public float C;
    public q C1;
    public float D;
    public final com.quizlet.data.interactor.folderwithcreator.m D1;
    public long E;
    public boolean E1;
    public float F;
    public final RectF F1;
    public boolean G;
    public View G1;
    public boolean H;
    public Matrix H1;
    public p I;
    public final ArrayList I1;
    public int J;
    public n K;
    public boolean L;
    public final androidx.constraintlayout.motion.utils.a M;
    public a V;
    public int W;
    public int c1;
    public boolean d1;
    public long e1;
    public float f1;
    public boolean g1;
    public ArrayList h1;
    public ArrayList i1;
    public CopyOnWriteArrayList j1;
    public int k1;
    public long l1;
    public float m1;
    public int n1;
    public float o1;
    public boolean p1;
    public l q;
    public int q1;
    public Interpolator r;
    public int r1;
    public float s;
    public int s1;
    public int t;
    public int t1;
    public int u;
    public int u1;
    public int v;
    public int v1;
    public int w;
    public float w1;
    public int x;
    public final androidx.constraintlayout.core.motion.utils.e x1;
    public boolean y;
    public boolean y1;
    public final HashMap z;
    public o z1;

    public r(@NonNull Context context) {
        super(context);
        this.r = null;
        this.s = DefinitionKt.NO_Float_VALUE;
        this.t = -1;
        this.u = -1;
        this.v = -1;
        this.w = 0;
        this.x = 0;
        this.y = true;
        this.z = new HashMap();
        this.A = 0L;
        this.B = 1.0f;
        this.C = DefinitionKt.NO_Float_VALUE;
        this.D = DefinitionKt.NO_Float_VALUE;
        this.F = DefinitionKt.NO_Float_VALUE;
        this.H = false;
        this.J = 0;
        this.L = false;
        androidx.constraintlayout.motion.utils.a aVar = new androidx.constraintlayout.motion.utils.a();
        androidx.constraintlayout.core.motion.utils.k kVar = new androidx.constraintlayout.core.motion.utils.k();
        kVar.a = false;
        aVar.a = kVar;
        this.M = aVar;
        new m(this);
        this.d1 = false;
        this.g1 = false;
        this.h1 = null;
        this.i1 = null;
        this.j1 = null;
        this.k1 = 0;
        this.l1 = -1L;
        this.m1 = DefinitionKt.NO_Float_VALUE;
        this.n1 = 0;
        this.o1 = DefinitionKt.NO_Float_VALUE;
        this.p1 = false;
        this.x1 = new androidx.constraintlayout.core.motion.utils.e(1);
        this.y1 = false;
        new HashMap();
        this.A1 = new Rect();
        this.B1 = false;
        this.C1 = q.a;
        com.quizlet.data.interactor.folderwithcreator.m mVar = new com.quizlet.data.interactor.folderwithcreator.m();
        mVar.e = this;
        mVar.a = new androidx.constraintlayout.core.widgets.f();
        mVar.b = new androidx.constraintlayout.core.widgets.f();
        mVar.c = null;
        mVar.d = null;
        this.D1 = mVar;
        this.E1 = false;
        this.F1 = new RectF();
        this.G1 = null;
        this.H1 = null;
        this.I1 = new ArrayList();
        J1 = isInEditMode();
        if (this.J != 0) {
            Log.e("MotionLayout", "CHECK: motion scene not set! set \"app:layoutDescription=\"@xml/file\"");
        }
    }

    public static Rect p(r rVar, androidx.constraintlayout.core.widgets.e eVar) {
        int iT = eVar.t();
        Rect rect = rVar.A1;
        rect.top = iT;
        rect.left = eVar.s();
        rect.right = eVar.r() + rect.left;
        rect.bottom = eVar.l() + rect.top;
        return rect;
    }

    @Override // androidx.core.view.r
    public final void c(int i, View view) {
    }

    /* JADX WARN: Removed duplicated region for block: B:100:0x016a  */
    /* JADX WARN: Removed duplicated region for block: B:103:0x0181  */
    /* JADX WARN: Removed duplicated region for block: B:315:0x06f2  */
    /* JADX WARN: Removed duplicated region for block: B:319:0x06fe  */
    /* JADX WARN: Removed duplicated region for block: B:322:0x0704  */
    /* JADX WARN: Removed duplicated region for block: B:334:0x0729  */
    /* JADX WARN: Removed duplicated region for block: B:351:0x074d  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00f9 A[PHI: r3
  0x00f9: PHI (r3v40 float) = (r3v39 float), (r3v41 float), (r3v41 float) binds: [B:53:0x00c7, B:64:0x00ed, B:66:0x00f1] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:78:0x0124  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x012d  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x0160  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x0162  */
    @Override // androidx.constraintlayout.widget.ConstraintLayout, android.view.ViewGroup, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void dispatchDraw(android.graphics.Canvas r55) {
        /*
            Method dump skipped, instructions count: 1957
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.constraintlayout.motion.widget.r.dispatchDraw(android.graphics.Canvas):void");
    }

    @Override // androidx.core.view.InterfaceC1061s
    public final void e(View view, int i, int i2, int i3, int i4, int i5, int[] iArr) {
        if (this.d1 || i != 0 || i2 != 0) {
            iArr[0] = iArr[0] + i3;
            iArr[1] = iArr[1] + i4;
        }
        this.d1 = false;
    }

    @Override // androidx.core.view.r
    public final void f(View view, int i, int i2, int i3, int i4, int i5) {
    }

    @Override // androidx.core.view.r
    public final boolean g(View view, View view2, int i, int i2) {
        return false;
    }

    public int[] getConstraintSetIds() {
        return null;
    }

    public int getCurrentState() {
        return this.u;
    }

    public ArrayList<t> getDefinedTransitions() {
        return null;
    }

    public a getDesignTool() {
        if (this.V == null) {
            this.V = new a();
        }
        return this.V;
    }

    public int getEndState() {
        return this.v;
    }

    public long getNanoTime() {
        return System.nanoTime();
    }

    public float getProgress() {
        return this.D;
    }

    public u getScene() {
        return null;
    }

    public int getStartState() {
        return this.t;
    }

    public float getTargetPosition() {
        return this.F;
    }

    public Bundle getTransitionState() {
        if (this.z1 == null) {
            this.z1 = new o(this);
        }
        o oVar = this.z1;
        r rVar = oVar.e;
        oVar.d = rVar.v;
        oVar.c = rVar.t;
        oVar.b = rVar.getVelocity();
        oVar.a = rVar.getProgress();
        o oVar2 = this.z1;
        oVar2.getClass();
        Bundle bundle = new Bundle();
        bundle.putFloat("motion.progress", oVar2.a);
        bundle.putFloat("motion.velocity", oVar2.b);
        bundle.putInt("motion.StartState", oVar2.c);
        bundle.putInt("motion.EndState", oVar2.d);
        return bundle;
    }

    public long getTransitionTimeMs() {
        return (long) (this.B * 1000.0f);
    }

    public float getVelocity() {
        return this.s;
    }

    @Override // androidx.core.view.r
    public final void h(View view, View view2, int i, int i2) {
        this.e1 = getNanoTime();
        this.f1 = DefinitionKt.NO_Float_VALUE;
    }

    @Override // androidx.core.view.r
    public final void i(View view, int i, int i2, int[] iArr, int i3) {
    }

    @Override // androidx.constraintlayout.widget.ConstraintLayout
    public final void l(int i) {
        this.k = null;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        Display display = getDisplay();
        if (display != null) {
            display.getRotation();
        }
        v();
        o oVar = this.z1;
        if (oVar != null) {
            if (this.B1) {
                post(new J(this, 9));
            } else {
                oVar.a();
            }
        }
    }

    @Override // android.view.ViewGroup
    public final boolean onInterceptTouchEvent(MotionEvent motionEvent) {
        return false;
    }

    @Override // androidx.constraintlayout.widget.ConstraintLayout, android.view.ViewGroup, android.view.View
    public final void onLayout(boolean z, int i, int i2, int i3, int i4) {
        this.y1 = true;
        try {
            super.onLayout(z, i, i2, i3, i4);
        } finally {
            this.y1 = false;
        }
    }

    @Override // androidx.constraintlayout.widget.ConstraintLayout, android.view.View
    public final void onMeasure(int i, int i2) {
        super.onMeasure(i, i2);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final boolean onNestedFling(View view, float f, float f2, boolean z) {
        return false;
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final boolean onNestedPreFling(View view, float f, float f2) {
        return false;
    }

    @Override // android.view.View
    public final void onRtlPropertiesChanged(int i) {
    }

    @Override // android.view.View
    public final boolean onTouchEvent(MotionEvent motionEvent) {
        return super.onTouchEvent(motionEvent);
    }

    @Override // androidx.constraintlayout.widget.ConstraintLayout, android.view.ViewGroup
    public final void onViewAdded(View view) {
        super.onViewAdded(view);
        if (view instanceof k) {
            k kVar = (k) view;
            if (this.j1 == null) {
                this.j1 = new CopyOnWriteArrayList();
            }
            this.j1.add(kVar);
            if (kVar.i) {
                if (this.h1 == null) {
                    this.h1 = new ArrayList();
                }
                this.h1.add(kVar);
            }
            if (kVar.j) {
                if (this.i1 == null) {
                    this.i1 = new ArrayList();
                }
                this.i1.add(kVar);
            }
        }
    }

    @Override // androidx.constraintlayout.widget.ConstraintLayout, android.view.ViewGroup
    public final void onViewRemoved(View view) {
        super.onViewRemoved(view);
        ArrayList arrayList = this.h1;
        if (arrayList != null) {
            arrayList.remove(view);
        }
        ArrayList arrayList2 = this.i1;
        if (arrayList2 != null) {
            arrayList2.remove(view);
        }
    }

    public final void q(float f) {
    }

    public final void r() {
        CopyOnWriteArrayList copyOnWriteArrayList;
        CopyOnWriteArrayList copyOnWriteArrayList2;
        if ((this.I == null && ((copyOnWriteArrayList2 = this.j1) == null || copyOnWriteArrayList2.isEmpty())) || this.o1 == this.C) {
            return;
        }
        if (this.n1 != -1 && (copyOnWriteArrayList = this.j1) != null) {
            Iterator it2 = copyOnWriteArrayList.iterator();
            while (it2.hasNext()) {
                ((p) it2.next()).getClass();
            }
        }
        this.n1 = -1;
        this.o1 = this.C;
        p pVar = this.I;
        if (pVar != null) {
            pVar.getClass();
        }
        CopyOnWriteArrayList copyOnWriteArrayList3 = this.j1;
        if (copyOnWriteArrayList3 != null) {
            Iterator it3 = copyOnWriteArrayList3.iterator();
            while (it3.hasNext()) {
                ((p) it3.next()).getClass();
            }
        }
    }

    @Override // androidx.constraintlayout.widget.ConstraintLayout, android.view.View, android.view.ViewParent
    public final void requestLayout() {
        boolean z = this.p1;
        super.requestLayout();
    }

    public final void s() {
        CopyOnWriteArrayList copyOnWriteArrayList;
        CopyOnWriteArrayList copyOnWriteArrayList2;
        if ((this.I != null || ((copyOnWriteArrayList2 = this.j1) != null && !copyOnWriteArrayList2.isEmpty())) && this.n1 == -1) {
            this.n1 = this.u;
            ArrayList arrayList = this.I1;
            int iIntValue = !arrayList.isEmpty() ? ((Integer) android.support.v4.media.session.a.e(1, arrayList)).intValue() : -1;
            int i = this.u;
            if (iIntValue != i && i != -1) {
                arrayList.add(Integer.valueOf(i));
            }
        }
        if (this.I == null && ((copyOnWriteArrayList = this.j1) == null || copyOnWriteArrayList.isEmpty())) {
            return;
        }
        ArrayList arrayList2 = this.I1;
        Iterator it2 = arrayList2.iterator();
        while (it2.hasNext()) {
            Integer num = (Integer) it2.next();
            p pVar = this.I;
            if (pVar != null) {
                num.intValue();
                pVar.getClass();
            }
            CopyOnWriteArrayList copyOnWriteArrayList3 = this.j1;
            if (copyOnWriteArrayList3 != null) {
                Iterator it3 = copyOnWriteArrayList3.iterator();
                while (it3.hasNext()) {
                    p pVar2 = (p) it3.next();
                    num.intValue();
                    pVar2.getClass();
                }
            }
        }
        arrayList2.clear();
    }

    public void setDebugMode(int i) {
        this.J = i;
        invalidate();
    }

    public void setDelayedApplicationOfInitialState(boolean z) {
        this.B1 = z;
    }

    public void setInteractionEnabled(boolean z) {
        this.y = z;
    }

    public void setInterpolatedProgress(float f) {
        setProgress(f);
    }

    public void setOnHide(float f) {
        ArrayList arrayList = this.i1;
        if (arrayList != null) {
            int size = arrayList.size();
            for (int i = 0; i < size; i++) {
                ((k) this.i1.get(i)).setProgress(f);
            }
        }
    }

    public void setOnShow(float f) {
        ArrayList arrayList = this.h1;
        if (arrayList != null) {
            int size = arrayList.size();
            for (int i = 0; i < size; i++) {
                ((k) this.h1.get(i)).setProgress(f);
            }
        }
    }

    public void setProgress(float f) {
        if (f < DefinitionKt.NO_Float_VALUE || f > 1.0f) {
            Log.w("MotionLayout", "Warning! Progress is defined for values between 0.0 and 1.0 inclusive");
        }
        if (!isAttachedToWindow()) {
            if (this.z1 == null) {
                this.z1 = new o(this);
            }
            this.z1.a = f;
            return;
        }
        q qVar = q.d;
        q qVar2 = q.c;
        if (f <= DefinitionKt.NO_Float_VALUE) {
            if (this.D == 1.0f && this.u == this.v) {
                setState(qVar2);
            }
            this.u = this.t;
            if (this.D == DefinitionKt.NO_Float_VALUE) {
                setState(qVar);
                return;
            }
            return;
        }
        if (f < 1.0f) {
            this.u = -1;
            setState(qVar2);
            return;
        }
        if (this.D == DefinitionKt.NO_Float_VALUE && this.u == this.t) {
            setState(qVar2);
        }
        this.u = this.v;
        if (this.D == 1.0f) {
            setState(qVar);
        }
    }

    public void setScene(u uVar) {
        int i;
        r rVar;
        int i2;
        SparseArray sparseArray;
        int[] iArr;
        int i3;
        uVar.b = k();
        com.quizlet.data.interactor.folderwithcreator.m mVar = this.D1;
        r rVar2 = (r) mVar.e;
        int i4 = rVar2.w;
        int i5 = rVar2.x;
        int mode = View.MeasureSpec.getMode(i4);
        int mode2 = View.MeasureSpec.getMode(i5);
        rVar2.u1 = mode;
        rVar2.v1 = mode2;
        mVar.e(i4, i5);
        if (!(rVar2.getParent() instanceof r) || mode != 1073741824 || mode2 != 1073741824) {
            mVar.e(i4, i5);
            rVar2.q1 = ((androidx.constraintlayout.core.widgets.f) mVar.a).r();
            rVar2.r1 = ((androidx.constraintlayout.core.widgets.f) mVar.a).l();
            rVar2.s1 = ((androidx.constraintlayout.core.widgets.f) mVar.b).r();
            int iL = ((androidx.constraintlayout.core.widgets.f) mVar.b).l();
            rVar2.t1 = iL;
            rVar2.p1 = (rVar2.q1 == rVar2.s1 && rVar2.r1 == iL) ? false : true;
        }
        int i6 = rVar2.q1;
        int i7 = rVar2.r1;
        int i8 = rVar2.u1;
        if (i8 == Integer.MIN_VALUE || i8 == 0) {
            i6 = (int) ((rVar2.w1 * (rVar2.s1 - i6)) + i6);
        }
        int i9 = rVar2.v1;
        if (i9 == Integer.MIN_VALUE || i9 == 0) {
            i7 = (int) ((rVar2.w1 * (rVar2.t1 - i7)) + i7);
        }
        int i10 = i7;
        androidx.constraintlayout.core.widgets.f fVar = (androidx.constraintlayout.core.widgets.f) mVar.a;
        rVar2.m(i4, i5, i6, i10, fVar.H0 || ((androidx.constraintlayout.core.widgets.f) mVar.b).H0, fVar.I0 || ((androidx.constraintlayout.core.widgets.f) mVar.b).I0);
        int childCount = rVar2.getChildCount();
        com.quizlet.data.interactor.folderwithcreator.m mVar2 = rVar2.D1;
        r rVar3 = (r) mVar2.e;
        int childCount2 = rVar3.getChildCount();
        rVar3.z.clear();
        SparseArray sparseArray2 = new SparseArray();
        int[] iArr2 = new int[childCount2];
        for (int i11 = 0; i11 < childCount2; i11++) {
            View childAt = rVar3.getChildAt(i11);
            j jVar = new j(childAt);
            int id = childAt.getId();
            iArr2[i11] = id;
            sparseArray2.put(id, jVar);
            rVar3.z.put(childAt, jVar);
        }
        int i12 = 0;
        while (i12 < childCount2) {
            View childAt2 = rVar3.getChildAt(i12);
            j jVar2 = (j) rVar3.z.get(childAt2);
            if (jVar2 == null) {
                i = childCount;
                rVar = rVar2;
                i2 = childCount2;
                sparseArray = sparseArray2;
                iArr = iArr2;
                i3 = i12;
            } else {
                if (((androidx.constraintlayout.widget.o) mVar2.c) != null) {
                    androidx.constraintlayout.core.widgets.e eVarK = com.quizlet.data.interactor.folderwithcreator.m.k((androidx.constraintlayout.core.widgets.f) mVar2.a, childAt2);
                    if (eVarK != null) {
                        Rect rectP = p(rVar3, eVarK);
                        androidx.constraintlayout.widget.o oVar = (androidx.constraintlayout.widget.o) mVar2.c;
                        iArr = iArr2;
                        int width = rVar3.getWidth();
                        i3 = i12;
                        int height = rVar3.getHeight();
                        i = childCount;
                        int i13 = oVar.a;
                        rVar = rVar2;
                        if (i13 != 0) {
                            j.c(rectP, jVar2.a, i13, width, height);
                        }
                        s sVar = jVar2.f;
                        sVar.c = DefinitionKt.NO_Float_VALUE;
                        sVar.d = DefinitionKt.NO_Float_VALUE;
                        jVar2.b(sVar);
                        sparseArray = sparseArray2;
                        i2 = childCount2;
                        sVar.c(rectP.left, rectP.top, rectP.width(), rectP.height());
                        androidx.constraintlayout.widget.j jVarH = oVar.h(jVar2.c);
                        sVar.a(jVarH);
                        androidx.constraintlayout.widget.l lVar = jVarH.c;
                        jVar2.l = lVar.g;
                        jVar2.h.c(rectP, oVar, i13, jVar2.c);
                        jVar2.B = jVarH.e.i;
                        jVar2.D = lVar.j;
                        jVar2.E = lVar.i;
                        Context context = jVar2.b.getContext();
                        int i14 = lVar.l;
                        jVar2.F = i14 != -2 ? i14 != -1 ? i14 != 0 ? i14 != 1 ? i14 != 2 ? i14 != 4 ? i14 != 5 ? null : new OvershootInterpolator() : new BounceInterpolator() : new DecelerateInterpolator() : new AccelerateInterpolator() : new AccelerateDecelerateInterpolator() : new i(androidx.constraintlayout.core.motion.utils.e.d(lVar.k)) : AnimationUtils.loadInterpolator(context, lVar.m);
                    } else {
                        i = childCount;
                        rVar = rVar2;
                        i2 = childCount2;
                        sparseArray = sparseArray2;
                        iArr = iArr2;
                        i3 = i12;
                        if (rVar3.J != 0) {
                            Log.e("MotionLayout", AbstractC3134e6.f() + "no widget for  " + AbstractC3134e6.h(childAt2) + " (" + childAt2.getClass().getName() + ")");
                        }
                    }
                } else {
                    i = childCount;
                    rVar = rVar2;
                    i2 = childCount2;
                    sparseArray = sparseArray2;
                    iArr = iArr2;
                    i3 = i12;
                }
                if (((androidx.constraintlayout.widget.o) mVar2.d) != null) {
                    androidx.constraintlayout.core.widgets.e eVarK2 = com.quizlet.data.interactor.folderwithcreator.m.k((androidx.constraintlayout.core.widgets.f) mVar2.b, childAt2);
                    if (eVarK2 != null) {
                        Rect rectP2 = p(rVar3, eVarK2);
                        androidx.constraintlayout.widget.o oVar2 = (androidx.constraintlayout.widget.o) mVar2.d;
                        int width2 = rVar3.getWidth();
                        int height2 = rVar3.getHeight();
                        int i15 = oVar2.a;
                        if (i15 != 0) {
                            j.c(rectP2, jVar2.a, i15, width2, height2);
                            rectP2 = jVar2.a;
                        }
                        s sVar2 = jVar2.g;
                        sVar2.c = 1.0f;
                        sVar2.d = 1.0f;
                        jVar2.b(sVar2);
                        sVar2.c(rectP2.left, rectP2.top, rectP2.width(), rectP2.height());
                        sVar2.a(oVar2.h(jVar2.c));
                        jVar2.i.c(rectP2, oVar2, i15, jVar2.c);
                    } else if (rVar3.J != 0) {
                        Log.e("MotionLayout", AbstractC3134e6.f() + "no widget for  " + AbstractC3134e6.h(childAt2) + " (" + childAt2.getClass().getName() + ")");
                    }
                }
            }
            i12 = i3 + 1;
            iArr2 = iArr;
            childCount = i;
            rVar2 = rVar;
            sparseArray2 = sparseArray;
            childCount2 = i2;
        }
        int i16 = childCount;
        r rVar4 = rVar2;
        SparseArray sparseArray3 = sparseArray2;
        int[] iArr3 = iArr2;
        int i17 = childCount2;
        int i18 = 0;
        while (i18 < i17) {
            SparseArray sparseArray4 = sparseArray3;
            j jVar3 = (j) sparseArray4.get(iArr3[i18]);
            int i19 = jVar3.f.k;
            if (i19 != -1) {
                j jVar4 = (j) sparseArray4.get(i19);
                jVar3.f.d(jVar4, jVar4.f);
                jVar3.g.d(jVar4, jVar4.g);
            }
            i18++;
            sparseArray3 = sparseArray4;
        }
        rVar4.H = true;
        SparseArray sparseArray5 = new SparseArray();
        int i20 = 0;
        while (true) {
            HashMap map = rVar4.z;
            int i21 = i16;
            if (i20 >= i21) {
                rVar4.getWidth();
                rVar4.getHeight();
                throw null;
            }
            View childAt3 = rVar4.getChildAt(i20);
            sparseArray5.put(childAt3.getId(), (j) map.get(childAt3));
            i20++;
            i16 = i21;
        }
    }

    public void setStartState(int i) {
        if (isAttachedToWindow()) {
            this.u = i;
            return;
        }
        if (this.z1 == null) {
            this.z1 = new o(this);
        }
        o oVar = this.z1;
        oVar.c = i;
        oVar.d = i;
    }

    public void setState(q qVar) {
        q qVar2 = q.d;
        if (qVar == qVar2 && this.u == -1) {
            return;
        }
        q qVar3 = this.C1;
        this.C1 = qVar;
        q qVar4 = q.c;
        if (qVar3 == qVar4 && qVar == qVar4) {
            r();
        }
        int iOrdinal = qVar3.ordinal();
        if (iOrdinal != 0 && iOrdinal != 1) {
            if (iOrdinal == 2 && qVar == qVar2) {
                s();
                return;
            }
            return;
        }
        if (qVar == qVar4) {
            r();
        }
        if (qVar == qVar2) {
            s();
        }
    }

    public void setTransition(int i) {
    }

    public void setTransitionDuration(int i) {
        Log.e("MotionLayout", "MotionScene not defined");
    }

    public void setTransitionListener(p pVar) {
        this.I = pVar;
    }

    public void setTransitionState(Bundle bundle) {
        if (this.z1 == null) {
            this.z1 = new o(this);
        }
        o oVar = this.z1;
        oVar.getClass();
        oVar.a = bundle.getFloat("motion.progress");
        oVar.b = bundle.getFloat("motion.velocity");
        oVar.c = bundle.getInt("motion.StartState");
        oVar.d = bundle.getInt("motion.EndState");
        if (isAttachedToWindow()) {
            this.z1.a();
        }
    }

    public final boolean t(float f, float f2, View view, MotionEvent motionEvent) {
        boolean z;
        boolean zOnTouchEvent;
        if (view instanceof ViewGroup) {
            ViewGroup viewGroup = (ViewGroup) view;
            for (int childCount = viewGroup.getChildCount() - 1; childCount >= 0; childCount--) {
                if (t((r3.getLeft() + f) - view.getScrollX(), (r3.getTop() + f2) - view.getScrollY(), viewGroup.getChildAt(childCount), motionEvent)) {
                    z = true;
                    break;
                }
            }
            z = false;
        } else {
            z = false;
        }
        if (!z) {
            RectF rectF = this.F1;
            rectF.set(f, f2, (view.getRight() + f) - view.getLeft(), (view.getBottom() + f2) - view.getTop());
            if (motionEvent.getAction() != 0 || rectF.contains(motionEvent.getX(), motionEvent.getY())) {
                float f3 = -f;
                float f4 = -f2;
                Matrix matrix = view.getMatrix();
                if (matrix.isIdentity()) {
                    motionEvent.offsetLocation(f3, f4);
                    zOnTouchEvent = view.onTouchEvent(motionEvent);
                    motionEvent.offsetLocation(-f3, -f4);
                } else {
                    MotionEvent motionEventObtain = MotionEvent.obtain(motionEvent);
                    motionEventObtain.offsetLocation(f3, f4);
                    if (this.H1 == null) {
                        this.H1 = new Matrix();
                    }
                    matrix.invert(this.H1);
                    motionEventObtain.transform(this.H1);
                    zOnTouchEvent = view.onTouchEvent(motionEventObtain);
                    motionEventObtain.recycle();
                }
                if (zOnTouchEvent) {
                    return true;
                }
            }
        }
        return z;
    }

    @Override // android.view.View
    public final String toString() {
        Context context = getContext();
        return AbstractC3134e6.g(context, this.t) + "->" + AbstractC3134e6.g(context, this.v) + " (pos:" + this.D + " Dpos/Dt:" + this.s;
    }

    public final void v() {
    }

    public final void w(int i, int i2) {
        if (isAttachedToWindow()) {
            return;
        }
        if (this.z1 == null) {
            this.z1 = new o(this);
        }
        o oVar = this.z1;
        oVar.c = i;
        oVar.d = i2;
    }

    public void setTransition(t tVar) {
        throw null;
    }
}
