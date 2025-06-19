package androidx.compose.ui.viewinterop;

import android.content.Context;
import android.graphics.Rect;
import android.graphics.Region;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import androidx.compose.material3.C0676l1;
import androidx.compose.runtime.C0775b0;
import androidx.compose.runtime.C0810n;
import androidx.compose.runtime.InterfaceC0802j;
import androidx.compose.ui.input.pointer.r;
import androidx.compose.ui.input.pointer.s;
import androidx.compose.ui.input.pointer.u;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.E;
import androidx.compose.ui.node.g0;
import androidx.compose.ui.node.h0;
import androidx.compose.ui.node.i0;
import androidx.compose.ui.platform.C0971v;
import androidx.compose.ui.platform.N;
import androidx.compose.ui.platform.p1;
import androidx.compose.ui.q;
import androidx.compose.ui.text.input.C;
import androidx.core.view.InterfaceC1061s;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_barcode.M5;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.T5;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import com.quizlet.quizletandroid.R;
import java.util.LinkedHashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public abstract class i extends ViewGroup implements InterfaceC1061s, InterfaceC0802j, h0 {
    public final androidx.compose.ui.input.nestedscroll.e a;
    public final View b;
    public final g0 c;
    public Function0 d;
    public boolean e;
    public Function0 f;
    public Function0 g;
    public q h;
    public Function1 i;
    public androidx.compose.ui.unit.b j;
    public Function1 k;
    public J l;
    public androidx.savedstate.f m;
    public final h n;
    public final h o;
    public Function1 p;
    public final int[] q;
    public int r;
    public int s;
    public final C0676l1 t;
    public boolean u;
    public final E v;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(Context context, C0810n c0810n, int i, androidx.compose.ui.input.nestedscroll.e eVar, View view, g0 g0Var) {
        super(context);
        int i2 = 2;
        int i3 = 1;
        int i4 = 0;
        this.a = eVar;
        this.b = view;
        this.c = g0Var;
        LinkedHashMap linkedHashMap = p1.a;
        setTag(R.id.androidx_compose_ui_view_composition_context, c0810n);
        setSaveFromParentEnabled(false);
        addView(view);
        this.d = g.d;
        this.f = g.c;
        this.g = g.b;
        androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
        this.h = nVar;
        this.j = M5.b();
        p pVar = (p) this;
        this.n = new h(pVar, i3);
        this.o = new h(pVar, i4);
        this.q = new int[2];
        this.r = Integer.MIN_VALUE;
        this.s = Integer.MIN_VALUE;
        this.t = new C0676l1();
        E e = new E(3);
        e.j = pVar;
        q qVarA = androidx.compose.ui.semantics.m.a(androidx.compose.ui.input.nestedscroll.f.a(nVar, k.a, eVar), true, a.e);
        r rVar = new r();
        rVar.b = new s(pVar, i4);
        u uVar = new u();
        u uVar2 = rVar.c;
        if (uVar2 != null) {
            uVar2.b = null;
        }
        rVar.c = uVar;
        uVar.b = rVar;
        setOnRequestDisallowInterceptTouchEvent$ui_release(uVar);
        q qVarL = AbstractC0897s.l(androidx.compose.ui.draw.g.e(qVarA.g(rVar), new androidx.activity.compose.g(pVar, e, pVar, 24)), new c(pVar, e, i2));
        e.Z(this.h.g(qVarL));
        this.i = new b(i3, e, qVarL);
        e.W(this.j);
        this.k = new C0775b0(e, 27);
        e.D = new c(pVar, e, i4);
        e.E = new s(pVar, i3);
        e.Y(new d(pVar, e));
        this.v = e;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final i0 getSnapshotObserver() {
        if (isAttachedToWindow()) {
            return ((C0971v) this.c).getSnapshotObserver();
        }
        W4.f("Expected AndroidViewHolder to be attached when observing reads.");
        throw null;
    }

    public static final int k(p pVar, int i, int i2, int i3) {
        return (i3 >= 0 || i == i2) ? View.MeasureSpec.makeMeasureSpec(kotlin.ranges.l.c(i3, i, i2), 1073741824) : (i3 != -2 || i2 == Integer.MAX_VALUE) ? (i3 != -1 || i2 == Integer.MAX_VALUE) ? View.MeasureSpec.makeMeasureSpec(0, 0) : View.MeasureSpec.makeMeasureSpec(i2, 1073741824) : View.MeasureSpec.makeMeasureSpec(i2, Integer.MIN_VALUE);
    }

    @Override // androidx.compose.runtime.InterfaceC0802j
    public final void a() {
        this.g.invoke();
    }

    @Override // androidx.compose.runtime.InterfaceC0802j
    public final void b() {
        this.f.invoke();
        removeAllViewsInLayout();
    }

    @Override // androidx.core.view.r
    public final void c(int i, View view) {
        C0676l1 c0676l1 = this.t;
        if (i == 1) {
            c0676l1.b = 0;
        } else {
            c0676l1.a = 0;
        }
    }

    @Override // androidx.compose.runtime.InterfaceC0802j
    public final void d() {
        View view = this.b;
        if (view.getParent() != this) {
            addView(view);
        } else {
            this.f.invoke();
        }
    }

    @Override // androidx.core.view.InterfaceC1061s
    public final void e(View view, int i, int i2, int i3, int i4, int i5, int[] iArr) {
        if (this.b.isNestedScrollingEnabled()) {
            float f = i;
            float f2 = -1;
            long jC = Q4.c(f * f2, i2 * f2);
            long jC2 = Q4.c(i3 * f2, i4 * f2);
            int i6 = i5 == 0 ? 1 : 2;
            androidx.compose.ui.input.nestedscroll.i iVar = this.a.a;
            androidx.compose.ui.input.nestedscroll.i iVar2 = null;
            if (iVar != null && iVar.m) {
                iVar2 = (androidx.compose.ui.input.nestedscroll.i) AbstractC0910f.k(iVar);
            }
            androidx.compose.ui.input.nestedscroll.i iVar3 = iVar2;
            long jS0 = iVar3 != null ? iVar3.s0(jC, jC2, i6) : 0L;
            iArr[0] = N.s(androidx.compose.ui.geometry.b.d(jS0));
            iArr[1] = N.s(androidx.compose.ui.geometry.b.e(jS0));
        }
    }

    @Override // androidx.core.view.r
    public final void f(View view, int i, int i2, int i3, int i4, int i5) {
        if (this.b.isNestedScrollingEnabled()) {
            float f = i;
            float f2 = -1;
            long jC = Q4.c(f * f2, i2 * f2);
            long jC2 = Q4.c(i3 * f2, i4 * f2);
            int i6 = i5 == 0 ? 1 : 2;
            androidx.compose.ui.input.nestedscroll.i iVar = this.a.a;
            androidx.compose.ui.input.nestedscroll.i iVar2 = null;
            if (iVar != null && iVar.m) {
                iVar2 = (androidx.compose.ui.input.nestedscroll.i) AbstractC0910f.k(iVar);
            }
            androidx.compose.ui.input.nestedscroll.i iVar3 = iVar2;
            if (iVar3 != null) {
                iVar3.s0(jC, jC2, i6);
            }
        }
    }

    @Override // androidx.core.view.r
    public final boolean g(View view, View view2, int i, int i2) {
        return ((i & 2) == 0 && (i & 1) == 0) ? false : true;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final boolean gatherTransparentRegion(Region region) {
        if (region == null) {
            return true;
        }
        int[] iArr = this.q;
        getLocationInWindow(iArr);
        int i = iArr[0];
        region.op(i, iArr[1], getWidth() + i, getHeight() + iArr[1], Region.Op.DIFFERENCE);
        return true;
    }

    @Override // android.view.ViewGroup, android.view.View
    @NotNull
    public CharSequence getAccessibilityClassName() {
        return getClass().getName();
    }

    @NotNull
    public final androidx.compose.ui.unit.b getDensity() {
        return this.j;
    }

    public final View getInteropView() {
        return this.b;
    }

    @NotNull
    public final E getLayoutNode() {
        return this.v;
    }

    @Override // android.view.View
    public ViewGroup.LayoutParams getLayoutParams() {
        ViewGroup.LayoutParams layoutParams = this.b.getLayoutParams();
        return layoutParams == null ? new ViewGroup.LayoutParams(-1, -1) : layoutParams;
    }

    public final J getLifecycleOwner() {
        return this.l;
    }

    @NotNull
    public final q getModifier() {
        return this.h;
    }

    @Override // android.view.ViewGroup
    public int getNestedScrollAxes() {
        C0676l1 c0676l1 = this.t;
        return c0676l1.b | c0676l1.a;
    }

    public final Function1<androidx.compose.ui.unit.b, Unit> getOnDensityChanged$ui_release() {
        return this.k;
    }

    public final Function1<q, Unit> getOnModifierChanged$ui_release() {
        return this.i;
    }

    public final Function1<Boolean, Unit> getOnRequestDisallowInterceptTouchEvent$ui_release() {
        return this.p;
    }

    @NotNull
    public final Function0<Unit> getRelease() {
        return this.g;
    }

    @NotNull
    public final Function0<Unit> getReset() {
        return this.f;
    }

    public final androidx.savedstate.f getSavedStateRegistryOwner() {
        return this.m;
    }

    @NotNull
    public final Function0<Unit> getUpdate() {
        return this.d;
    }

    @NotNull
    public final View getView() {
        return this.b;
    }

    @Override // androidx.core.view.r
    public final void h(View view, View view2, int i, int i2) {
        C0676l1 c0676l1 = this.t;
        if (i2 == 1) {
            c0676l1.b = i;
        } else {
            c0676l1.a = i;
        }
    }

    @Override // androidx.core.view.r
    public final void i(View view, int i, int i2, int[] iArr, int i3) {
        if (this.b.isNestedScrollingEnabled()) {
            float f = i;
            float f2 = -1;
            long jC = Q4.c(f * f2, i2 * f2);
            int i4 = i3 == 0 ? 1 : 2;
            androidx.compose.ui.input.nestedscroll.i iVar = this.a.a;
            androidx.compose.ui.input.nestedscroll.i iVar2 = null;
            if (iVar != null && iVar.m) {
                iVar2 = (androidx.compose.ui.input.nestedscroll.i) AbstractC0910f.k(iVar);
            }
            long jL = iVar2 != null ? iVar2.L(i4, jC) : 0L;
            iArr[0] = N.s(androidx.compose.ui.geometry.b.d(jL));
            iArr[1] = N.s(androidx.compose.ui.geometry.b.e(jL));
        }
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final ViewParent invalidateChildInParent(int[] iArr, Rect rect) {
        super.invalidateChildInParent(iArr, rect);
        if (!this.u) {
            this.v.z();
            return null;
        }
        this.b.postOnAnimation(new C(this.o, 1));
        return null;
    }

    @Override // android.view.View
    public final boolean isNestedScrollingEnabled() {
        return this.b.isNestedScrollingEnabled();
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        this.n.invoke();
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final void onDescendantInvalidated(View view, View view2) {
        super.onDescendantInvalidated(view, view2);
        if (!this.u) {
            this.v.z();
        } else {
            this.b.postOnAnimation(new C(this.o, 1));
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onDetachedFromWindow() throws Throwable {
        super.onDetachedFromWindow();
        getSnapshotObserver().a.c(this);
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onLayout(boolean z, int i, int i2, int i3, int i4) {
        this.b.layout(0, 0, i3 - i, i4 - i2);
    }

    @Override // android.view.View
    public final void onMeasure(int i, int i2) {
        View view = this.b;
        if (view.getParent() != this) {
            setMeasuredDimension(View.MeasureSpec.getSize(i), View.MeasureSpec.getSize(i2));
            return;
        }
        if (view.getVisibility() == 8) {
            setMeasuredDimension(0, 0);
            return;
        }
        view.measure(i, i2);
        setMeasuredDimension(view.getMeasuredWidth(), view.getMeasuredHeight());
        this.r = i;
        this.s = i2;
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final boolean onNestedFling(View view, float f, float f2, boolean z) {
        if (!this.b.isNestedScrollingEnabled()) {
            return false;
        }
        kotlinx.coroutines.E.A(this.a.c(), null, null, new e(z, this, T5.b(f * (-1.0f), f2 * (-1.0f)), null), 3);
        return false;
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final boolean onNestedPreFling(View view, float f, float f2) {
        if (!this.b.isNestedScrollingEnabled()) {
            return false;
        }
        kotlinx.coroutines.E.A(this.a.c(), null, null, new f(this, T5.b(f * (-1.0f), f2 * (-1.0f)), null), 3);
        return false;
    }

    @Override // android.view.View
    public final void onWindowVisibilityChanged(int i) {
        super.onWindowVisibilityChanged(i);
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final void requestDisallowInterceptTouchEvent(boolean z) {
        Function1 function1 = this.p;
        if (function1 != null) {
            function1.invoke(Boolean.valueOf(z));
        }
        super.requestDisallowInterceptTouchEvent(z);
    }

    public final void setDensity(@NotNull androidx.compose.ui.unit.b bVar) {
        if (bVar != this.j) {
            this.j = bVar;
            Function1 function1 = this.k;
            if (function1 != null) {
                function1.invoke(bVar);
            }
        }
    }

    public final void setLifecycleOwner(J j) {
        if (j != this.l) {
            this.l = j;
            p0.n(this, j);
        }
    }

    public final void setModifier(@NotNull q qVar) {
        if (qVar != this.h) {
            this.h = qVar;
            Function1 function1 = this.i;
            if (function1 != null) {
                function1.invoke(qVar);
            }
        }
    }

    public final void setOnDensityChanged$ui_release(Function1<? super androidx.compose.ui.unit.b, Unit> function1) {
        this.k = function1;
    }

    public final void setOnModifierChanged$ui_release(Function1<? super q, Unit> function1) {
        this.i = function1;
    }

    public final void setOnRequestDisallowInterceptTouchEvent$ui_release(Function1<? super Boolean, Unit> function1) {
        this.p = function1;
    }

    public final void setRelease(@NotNull Function0<Unit> function0) {
        this.g = function0;
    }

    public final void setReset(@NotNull Function0<Unit> function0) {
        this.f = function0;
    }

    public final void setSavedStateRegistryOwner(androidx.savedstate.f fVar) {
        if (fVar != this.m) {
            this.m = fVar;
            AbstractC3347h2.e(this, fVar);
        }
    }

    public final void setUpdate(@NotNull Function0<Unit> function0) {
        this.d = function0;
        this.e = true;
        this.n.invoke();
    }

    @Override // android.view.ViewGroup
    public final boolean shouldDelayChildPressedState() {
        return true;
    }

    @Override // androidx.compose.ui.node.h0
    public final boolean u() {
        return isAttachedToWindow();
    }
}
