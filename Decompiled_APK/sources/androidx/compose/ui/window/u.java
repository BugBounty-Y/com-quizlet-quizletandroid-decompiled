package androidx.compose.ui.window;

import android.graphics.Rect;
import android.os.Build;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.WindowManager;
import androidx.camera.camera2.internal.C0132i;
import androidx.compose.material3.C0634i2;
import androidx.compose.runtime.AbstractC0827t;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.E;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.L0;
import androidx.compose.ui.platform.AbstractC0930a;
import androidx.compose.ui.text.C0981a;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.UUID;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.I;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class u extends AbstractC0930a {
    public Function0 a;
    public y b;
    public String c;
    public final View d;
    public final w e;
    public final WindowManager f;
    public final WindowManager.LayoutParams g;
    public x h;
    public androidx.compose.ui.unit.k i;
    public final InterfaceC0773a0 j;
    public final InterfaceC0773a0 k;
    public androidx.compose.ui.unit.i l;
    public final E m;
    public final Rect n;
    public final androidx.compose.runtime.snapshots.v o;
    public Object p;
    public final InterfaceC0773a0 q;
    public boolean r;
    public final int[] s;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(Function0 function0, y yVar, String str, View view, androidx.compose.ui.unit.b bVar, x xVar, UUID uuid) {
        super(view.getContext(), null);
        w vVar = Build.VERSION.SDK_INT >= 29 ? new v() : new w();
        this.a = function0;
        this.b = yVar;
        this.c = str;
        this.d = view;
        this.e = vVar;
        Object systemService = view.getContext().getSystemService("window");
        Intrinsics.e(systemService, "null cannot be cast to non-null type android.view.WindowManager");
        this.f = (WindowManager) systemService;
        WindowManager.LayoutParams layoutParams = new WindowManager.LayoutParams();
        layoutParams.gravity = 8388659;
        y yVar2 = this.b;
        boolean zC = l.c(view);
        boolean z = yVar2.b;
        int i = yVar2.a;
        if (z && zC) {
            i |= 8192;
        } else if (z && !zC) {
            i &= -8193;
        }
        layoutParams.flags = i;
        layoutParams.type = 1002;
        layoutParams.token = view.getApplicationWindowToken();
        layoutParams.width = -2;
        layoutParams.height = -2;
        layoutParams.format = -3;
        layoutParams.setTitle(view.getContext().getResources().getString(R.string.default_popup_window_title));
        this.g = layoutParams;
        this.h = xVar;
        this.i = androidx.compose.ui.unit.k.a;
        this.j = C0776c.z(null);
        this.k = C0776c.z(null);
        this.m = C0776c.q(new androidx.compose.ui.input.nestedscroll.b(this, 14));
        this.n = new Rect();
        this.o = new androidx.compose.runtime.snapshots.v(new j(this, 2));
        setId(android.R.id.content);
        p0.n(this, p0.f(view));
        p0.o(this, p0.g(view));
        AbstractC3347h2.e(this, AbstractC3347h2.b(view));
        setTag(R.id.compose_view_saveable_id_tag, "Popup:" + uuid);
        setClipChildren(false);
        setElevation(bVar.c0((float) 8));
        setOutlineProvider(new C0634i2(4));
        this.q = C0776c.z(p.a);
        this.s = new int[2];
    }

    private final Function2<InterfaceC0806l, Integer, Unit> getContent() {
        return (Function2) ((L0) this.q).getValue();
    }

    private final int getDisplayHeight() {
        return Math.round(getContext().getResources().getConfiguration().screenHeightDp * getContext().getResources().getDisplayMetrics().density);
    }

    private final int getDisplayWidth() {
        return Math.round(getContext().getResources().getConfiguration().screenWidthDp * getContext().getResources().getDisplayMetrics().density);
    }

    public static /* synthetic */ void getParams$ui_release$annotations() {
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final androidx.compose.ui.layout.r getParentLayoutCoordinates() {
        return (androidx.compose.ui.layout.r) ((L0) this.k).getValue();
    }

    private final void setContent(Function2<? super InterfaceC0806l, ? super Integer, Unit> function2) {
        ((L0) this.q).setValue(function2);
    }

    private final void setParentLayoutCoordinates(androidx.compose.ui.layout.r rVar) {
        ((L0) this.k).setValue(rVar);
    }

    @Override // androidx.compose.ui.platform.AbstractC0930a
    public final void Content(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-857613600);
        if ((((c0814p.h(this) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            getContent().invoke(c0814p, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0981a(this, i, 2);
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public final boolean dispatchKeyEvent(KeyEvent keyEvent) {
        KeyEvent.DispatcherState keyDispatcherState;
        if (keyEvent.getKeyCode() == 4 && this.b.c) {
            if (getKeyDispatcherState() == null) {
                return super.dispatchKeyEvent(keyEvent);
            }
            if (keyEvent.getAction() == 0 && keyEvent.getRepeatCount() == 0) {
                KeyEvent.DispatcherState keyDispatcherState2 = getKeyDispatcherState();
                if (keyDispatcherState2 != null) {
                    keyDispatcherState2.startTracking(keyEvent, this);
                }
                return true;
            }
            if (keyEvent.getAction() == 1 && (keyDispatcherState = getKeyDispatcherState()) != null && keyDispatcherState.isTracking(keyEvent) && !keyEvent.isCanceled()) {
                Function0 function0 = this.a;
                if (function0 != null) {
                    function0.invoke();
                }
                return true;
            }
        }
        return super.dispatchKeyEvent(keyEvent);
    }

    public final void e(AbstractC0827t abstractC0827t, Function2 function2) {
        setParentCompositionContext(abstractC0827t);
        setContent(function2);
        this.r = true;
    }

    public final void f(Function0 function0, y yVar, String str, androidx.compose.ui.unit.k kVar) {
        int i;
        this.a = function0;
        this.c = str;
        if (!Intrinsics.b(this.b, yVar)) {
            boolean z = yVar.f;
            WindowManager.LayoutParams layoutParams = this.g;
            if (z && !this.b.f) {
                layoutParams.width = -2;
                layoutParams.height = -2;
            }
            this.b = yVar;
            boolean zC = l.c(this.d);
            boolean z2 = yVar.b;
            int i2 = yVar.a;
            if (z2 && zC) {
                i2 |= 8192;
            } else if (z2 && !zC) {
                i2 &= -8193;
            }
            layoutParams.flags = i2;
            this.e.getClass();
            this.f.updateViewLayout(this, layoutParams);
        }
        int iOrdinal = kVar.ordinal();
        if (iOrdinal != 0) {
            i = 1;
            if (iOrdinal != 1) {
                throw new NoWhenBranchMatchedException();
            }
        } else {
            i = 0;
        }
        super.setLayoutDirection(i);
    }

    public final void g() {
        androidx.compose.ui.layout.r parentLayoutCoordinates = getParentLayoutCoordinates();
        if (parentLayoutCoordinates != null) {
            if (!parentLayoutCoordinates.k()) {
                parentLayoutCoordinates = null;
            }
            if (parentLayoutCoordinates == null) {
                return;
            }
            long jT = parentLayoutCoordinates.t();
            long jD = parentLayoutCoordinates.d(0L);
            long jB = P5.b(Math.round(androidx.compose.ui.geometry.b.d(jD)), Math.round(androidx.compose.ui.geometry.b.e(jD)));
            int i = (int) (jB >> 32);
            int i2 = (int) (jB & 4294967295L);
            androidx.compose.ui.unit.i iVar = new androidx.compose.ui.unit.i(i, i2, ((int) (jT >> 32)) + i, ((int) (jT & 4294967295L)) + i2);
            if (iVar.equals(this.l)) {
                return;
            }
            this.l = iVar;
            i();
        }
    }

    public final boolean getCanCalculatePosition() {
        return ((Boolean) this.m.getValue()).booleanValue();
    }

    @NotNull
    public final WindowManager.LayoutParams getParams$ui_release() {
        return this.g;
    }

    @NotNull
    public final androidx.compose.ui.unit.k getParentLayoutDirection() {
        return this.i;
    }

    /* renamed from: getPopupContentSize-bOM6tXw, reason: not valid java name */
    public final androidx.compose.ui.unit.j m5getPopupContentSizebOM6tXw() {
        return (androidx.compose.ui.unit.j) ((L0) this.j).getValue();
    }

    @NotNull
    public final x getPositionProvider() {
        return this.h;
    }

    @Override // androidx.compose.ui.platform.AbstractC0930a
    public boolean getShouldCreateCompositionOnAttachedToWindow() {
        return this.r;
    }

    @NotNull
    public AbstractC0930a getSubCompositionView() {
        return this;
    }

    @NotNull
    public final String getTestTag() {
        return this.c;
    }

    public /* bridge */ /* synthetic */ View getViewRoot() {
        return null;
    }

    public final void h(androidx.compose.ui.layout.r rVar) {
        setParentLayoutCoordinates(rVar);
        g();
    }

    public final void i() {
        androidx.compose.ui.unit.j jVarM5getPopupContentSizebOM6tXw;
        androidx.compose.ui.unit.i iVar = this.l;
        if (iVar == null || (jVarM5getPopupContentSizebOM6tXw = m5getPopupContentSizebOM6tXw()) == null) {
            return;
        }
        w wVar = this.e;
        wVar.getClass();
        View view = this.d;
        Rect rect = this.n;
        view.getWindowVisibleDisplayFrame(rect);
        long jA = R5.a(rect.right - rect.left, rect.bottom - rect.top);
        I i = new I();
        i.a = 0L;
        this.o.d(this, c.g, new t(i, this, iVar, jA, jVarM5getPopupContentSizebOM6tXw.a));
        WindowManager.LayoutParams layoutParams = this.g;
        long j = i.a;
        layoutParams.x = (int) (j >> 32);
        layoutParams.y = (int) (j & 4294967295L);
        if (this.b.e) {
            wVar.a(this, (int) (jA >> 32), (int) (jA & 4294967295L));
        }
        this.f.updateViewLayout(this, layoutParams);
    }

    @Override // androidx.compose.ui.platform.AbstractC0930a
    public final void internalOnLayout$ui_release(boolean z, int i, int i2, int i3, int i4) {
        View childAt;
        super.internalOnLayout$ui_release(z, i, i2, i3, i4);
        if (this.b.f || (childAt = getChildAt(0)) == null) {
            return;
        }
        WindowManager.LayoutParams layoutParams = this.g;
        layoutParams.width = childAt.getMeasuredWidth();
        layoutParams.height = childAt.getMeasuredHeight();
        this.e.getClass();
        this.f.updateViewLayout(this, layoutParams);
    }

    @Override // androidx.compose.ui.platform.AbstractC0930a
    public final void internalOnMeasure$ui_release(int i, int i2) {
        if (this.b.f) {
            super.internalOnMeasure$ui_release(i, i2);
        } else {
            super.internalOnMeasure$ui_release(View.MeasureSpec.makeMeasureSpec(getDisplayWidth(), Integer.MIN_VALUE), View.MeasureSpec.makeMeasureSpec(getDisplayHeight(), Integer.MIN_VALUE));
        }
    }

    @Override // androidx.compose.ui.platform.AbstractC0930a, android.view.ViewGroup, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        this.o.e();
        if (!this.b.c || Build.VERSION.SDK_INT < 33) {
            return;
        }
        if (this.p == null) {
            this.p = m.a(this.a);
        }
        m.b(this, this.p);
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        androidx.compose.runtime.snapshots.v vVar = this.o;
        C0132i c0132i = vVar.h;
        if (c0132i != null) {
            c0132i.f();
        }
        vVar.b();
        if (Build.VERSION.SDK_INT >= 33) {
            m.c(this, this.p);
        }
        this.p = null;
    }

    @Override // android.view.View
    public final boolean onTouchEvent(MotionEvent motionEvent) {
        if (!this.b.d) {
            return super.onTouchEvent(motionEvent);
        }
        if (motionEvent != null && motionEvent.getAction() == 0 && (motionEvent.getX() < DefinitionKt.NO_Float_VALUE || motionEvent.getX() >= getWidth() || motionEvent.getY() < DefinitionKt.NO_Float_VALUE || motionEvent.getY() >= getHeight())) {
            Function0 function0 = this.a;
            if (function0 != null) {
                function0.invoke();
            }
            return true;
        }
        if (motionEvent == null || motionEvent.getAction() != 4) {
            return super.onTouchEvent(motionEvent);
        }
        Function0 function02 = this.a;
        if (function02 != null) {
            function02.invoke();
        }
        return true;
    }

    @Override // android.view.View
    public void setLayoutDirection(int i) {
    }

    public final void setParentLayoutDirection(@NotNull androidx.compose.ui.unit.k kVar) {
        this.i = kVar;
    }

    /* renamed from: setPopupContentSize-fhxjrPA, reason: not valid java name */
    public final void m6setPopupContentSizefhxjrPA(androidx.compose.ui.unit.j jVar) {
        ((L0) this.j).setValue(jVar);
    }

    public final void setPositionProvider(@NotNull x xVar) {
        this.h = xVar;
    }

    public final void setTestTag(@NotNull String str) {
        this.c = str;
    }
}
