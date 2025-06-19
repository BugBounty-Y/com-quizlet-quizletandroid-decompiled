package androidx.compose.ui.platform;

import android.content.Context;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.util.AttributeSet;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import androidx.appcompat.view.menu.ViewOnAttachStateChangeListenerC0068e;
import androidx.compose.animation.C0281h;
import androidx.compose.foundation.C0473q;
import androidx.compose.runtime.AbstractC0827t;
import androidx.compose.runtime.C0799h0;
import androidx.compose.runtime.C0832v0;
import androidx.compose.runtime.EnumC0817q0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.InterfaceC0819s;
import com.google.android.gms.internal.mlkit_vision_barcode.G6;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import com.quizlet.quizletandroid.R;
import java.lang.ref.WeakReference;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C4977c0;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.compose.ui.platform.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0930a extends ViewGroup {
    public static final int $stable = 8;
    private WeakReference<AbstractC0827t> cachedViewTreeCompositionContext;
    private InterfaceC0819s composition;
    private boolean creatingComposition;
    private Function0<Unit> disposeViewCompositionStrategy;
    private boolean isTransitionGroupSet;
    private AbstractC0827t parentContext;
    private IBinder previousAttachedWindowToken;
    private boolean showLayoutBounds;

    public AbstractC0930a(@NotNull Context context) {
        this(context, null);
    }

    private static /* synthetic */ void getDisposeViewCompositionStrategy$annotations() {
    }

    public static /* synthetic */ void getShowLayoutBounds$annotations() {
    }

    private final void setParentContext(AbstractC0827t abstractC0827t) {
        if (this.parentContext != abstractC0827t) {
            this.parentContext = abstractC0827t;
            if (abstractC0827t != null) {
                this.cachedViewTreeCompositionContext = null;
            }
            InterfaceC0819s interfaceC0819s = this.composition;
            if (interfaceC0819s != null) {
                interfaceC0819s.dispose();
                this.composition = null;
                if (isAttachedToWindow()) {
                    b();
                }
            }
        }
    }

    private final void setPreviousAttachedWindowToken(IBinder iBinder) {
        if (this.previousAttachedWindowToken != iBinder) {
            this.previousAttachedWindowToken = iBinder;
            this.cachedViewTreeCompositionContext = null;
        }
    }

    public abstract void Content(InterfaceC0806l interfaceC0806l, int i);

    public final void a() {
        if (this.creatingComposition) {
            return;
        }
        throw new UnsupportedOperationException("Cannot add views to " + getClass().getSimpleName() + "; only Compose content is supported");
    }

    @Override // android.view.ViewGroup
    public void addView(View view) {
        a();
        super.addView(view);
    }

    @Override // android.view.ViewGroup
    public boolean addViewInLayout(View view, int i, ViewGroup.LayoutParams layoutParams) {
        a();
        return super.addViewInLayout(view, i, layoutParams);
    }

    public final void b() {
        if (this.composition == null) {
            try {
                this.creatingComposition = true;
                this.composition = v1.a(this, c(), new androidx.compose.runtime.internal.d(true, -656146368, new C0281h(this, 28)));
            } finally {
                this.creatingComposition = false;
            }
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final AbstractC0827t c() {
        C0832v0 c0832v0;
        CoroutineContext coroutineContext;
        C0799h0 c0799h0;
        int i = 1;
        AbstractC0827t abstractC0827tB = this.parentContext;
        if (abstractC0827tB == null) {
            abstractC0827tB = p1.b(this);
            if (abstractC0827tB == null) {
                for (ViewParent parent = getParent(); abstractC0827tB == null && (parent instanceof View); parent = parent.getParent()) {
                    abstractC0827tB = p1.b((View) parent);
                }
            }
            if (abstractC0827tB != null) {
                AbstractC0827t abstractC0827t = (!(abstractC0827tB instanceof C0832v0) || ((EnumC0817q0) ((C0832v0) abstractC0827tB).u.getValue()).compareTo(EnumC0817q0.b) > 0) ? abstractC0827tB : null;
                if (abstractC0827t != null) {
                    this.cachedViewTreeCompositionContext = new WeakReference<>(abstractC0827t);
                }
            } else {
                abstractC0827tB = null;
            }
            if (abstractC0827tB == null) {
                WeakReference<AbstractC0827t> weakReference = this.cachedViewTreeCompositionContext;
                if (weakReference == null || (abstractC0827tB = weakReference.get()) == null || ((abstractC0827tB instanceof C0832v0) && ((EnumC0817q0) ((C0832v0) abstractC0827tB).u.getValue()).compareTo(EnumC0817q0.b) <= 0)) {
                    abstractC0827tB = null;
                }
                if (abstractC0827tB == null) {
                    if (!isAttachedToWindow()) {
                        W4.f("Cannot locate windowRecomposer; View " + this + " is not attached to a window");
                        throw null;
                    }
                    Object parent2 = getParent();
                    View view = this;
                    while (parent2 instanceof View) {
                        View view2 = (View) parent2;
                        if (view2.getId() == 16908290) {
                            break;
                        }
                        view = view2;
                        parent2 = view2.getParent();
                    }
                    AbstractC0827t abstractC0827tB2 = p1.b(view);
                    if (abstractC0827tB2 == null) {
                        ((g1) i1.a.get()).getClass();
                        kotlin.coroutines.n nVar = kotlin.coroutines.n.a;
                        nVar.get(kotlin.coroutines.j.a1);
                        kotlin.u uVar = Z.l;
                        if (Looper.myLooper() == Looper.getMainLooper()) {
                            coroutineContext = (CoroutineContext) Z.l.getValue();
                        } else {
                            coroutineContext = (CoroutineContext) Z.m.get();
                            if (coroutineContext == null) {
                                throw new IllegalStateException("no AndroidUiDispatcher for this thread");
                            }
                        }
                        CoroutineContext coroutineContextPlus = coroutineContext.plus(nVar);
                        androidx.compose.runtime.W w = (androidx.compose.runtime.W) coroutineContextPlus.get(androidx.compose.runtime.V.b);
                        if (w != null) {
                            C0799h0 c0799h02 = new C0799h0(w);
                            androidx.browser.customtabs.k kVar = c0799h02.b;
                            synchronized (kVar.b) {
                                kVar.a = false;
                                Unit unit = Unit.a;
                                c0799h0 = c0799h02;
                            }
                        } else {
                            c0799h0 = 0;
                        }
                        kotlin.jvm.internal.J j = new kotlin.jvm.internal.J();
                        CoroutineContext c0980z0 = (androidx.compose.ui.r) coroutineContextPlus.get(androidx.compose.ui.b.p);
                        if (c0980z0 == null) {
                            c0980z0 = new C0980z0();
                            j.a = c0980z0;
                        }
                        if (c0799h0 != 0) {
                            nVar = c0799h0;
                        }
                        CoroutineContext coroutineContextPlus2 = coroutineContextPlus.plus(nVar).plus(c0980z0);
                        c0832v0 = new C0832v0(coroutineContextPlus2);
                        synchronized (c0832v0.c) {
                            c0832v0.t = true;
                            Unit unit2 = Unit.a;
                        }
                        kotlinx.coroutines.internal.d dVarC = kotlinx.coroutines.E.c(coroutineContextPlus2);
                        androidx.lifecycle.J jF = androidx.lifecycle.p0.f(view);
                        androidx.lifecycle.C lifecycle = jF != null ? jF.getLifecycle() : null;
                        if (lifecycle == null) {
                            W4.g("ViewTreeLifecycleOwner not found from " + view);
                            throw null;
                        }
                        view.addOnAttachStateChangeListener(new V0(view, c0832v0, i));
                        lifecycle.a(new m1(dVarC, c0799h0, c0832v0, j, view));
                        view.setTag(R.id.androidx_compose_ui_view_composition_context, c0832v0);
                        C4977c0 c4977c0 = C4977c0.a;
                        Handler handler = view.getHandler();
                        int i2 = kotlinx.coroutines.android.e.a;
                        view.addOnAttachStateChangeListener(new ViewOnAttachStateChangeListenerC0068e(kotlinx.coroutines.E.A(c4977c0, new kotlinx.coroutines.android.d(handler, "windowRecomposer cleanup", false).e, null, new h1(c0832v0, view, null), 2), 4));
                    } else {
                        if (!(abstractC0827tB2 instanceof C0832v0)) {
                            throw new IllegalStateException("root viewTreeParentCompositionContext is not a Recomposer");
                        }
                        c0832v0 = (C0832v0) abstractC0827tB2;
                    }
                    C0832v0 c0832v02 = ((EnumC0817q0) c0832v0.u.getValue()).compareTo(EnumC0817q0.b) > 0 ? c0832v0 : null;
                    if (c0832v02 != null) {
                        this.cachedViewTreeCompositionContext = new WeakReference<>(c0832v02);
                    }
                    return c0832v0;
                }
            }
        }
        return abstractC0827tB;
    }

    public final void createComposition() {
        if (this.parentContext == null && !isAttachedToWindow()) {
            throw new IllegalStateException("createComposition requires either a parent reference or the View to be attachedto a window. Attach the View or call setParentCompositionReference.");
        }
        b();
    }

    public final void disposeComposition() {
        InterfaceC0819s interfaceC0819s = this.composition;
        if (interfaceC0819s != null) {
            interfaceC0819s.dispose();
        }
        this.composition = null;
        requestLayout();
    }

    public final boolean getHasComposition() {
        return this.composition != null;
    }

    public boolean getShouldCreateCompositionOnAttachedToWindow() {
        return true;
    }

    public final boolean getShowLayoutBounds() {
        return this.showLayoutBounds;
    }

    public void internalOnLayout$ui_release(boolean z, int i, int i2, int i3, int i4) {
        View childAt = getChildAt(0);
        if (childAt != null) {
            childAt.layout(getPaddingLeft(), getPaddingTop(), (i3 - i) - getPaddingRight(), (i4 - i2) - getPaddingBottom());
        }
    }

    public void internalOnMeasure$ui_release(int i, int i2) {
        View childAt = getChildAt(0);
        if (childAt == null) {
            super.onMeasure(i, i2);
            return;
        }
        childAt.measure(View.MeasureSpec.makeMeasureSpec(Math.max(0, (View.MeasureSpec.getSize(i) - getPaddingLeft()) - getPaddingRight()), View.MeasureSpec.getMode(i)), View.MeasureSpec.makeMeasureSpec(Math.max(0, (View.MeasureSpec.getSize(i2) - getPaddingTop()) - getPaddingBottom()), View.MeasureSpec.getMode(i2)));
        setMeasuredDimension(getPaddingRight() + getPaddingLeft() + childAt.getMeasuredWidth(), getPaddingBottom() + getPaddingTop() + childAt.getMeasuredHeight());
    }

    @Override // android.view.ViewGroup
    public boolean isTransitionGroup() {
        return !this.isTransitionGroupSet || super.isTransitionGroup();
    }

    @Override // android.view.ViewGroup, android.view.View
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        setPreviousAttachedWindowToken(getWindowToken());
        if (getShouldCreateCompositionOnAttachedToWindow()) {
            b();
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onLayout(boolean z, int i, int i2, int i3, int i4) {
        internalOnLayout$ui_release(z, i, i2, i3, i4);
    }

    @Override // android.view.View
    public final void onMeasure(int i, int i2) {
        b();
        internalOnMeasure$ui_release(i, i2);
    }

    @Override // android.view.View
    public void onRtlPropertiesChanged(int i) {
        View childAt = getChildAt(0);
        if (childAt == null) {
            return;
        }
        childAt.setLayoutDirection(i);
    }

    public final void setParentCompositionContext(AbstractC0827t abstractC0827t) {
        setParentContext(abstractC0827t);
    }

    public final void setShowLayoutBounds(boolean z) {
        this.showLayoutBounds = z;
        KeyEvent.Callback childAt = getChildAt(0);
        if (childAt != null) {
            ((C0971v) ((androidx.compose.ui.node.g0) childAt)).setShowLayoutBounds(z);
        }
    }

    @Override // android.view.ViewGroup
    public void setTransitionGroup(boolean z) {
        super.setTransitionGroup(z);
        this.isTransitionGroupSet = true;
    }

    public final void setViewCompositionStrategy(@NotNull W0 w0) {
        Function0<Unit> function0 = this.disposeViewCompositionStrategy;
        if (function0 != null) {
            function0.invoke();
        }
        this.disposeViewCompositionStrategy = w0.a(this);
    }

    @Override // android.view.ViewGroup
    public boolean shouldDelayChildPressedState() {
        return false;
    }

    public AbstractC0930a(Context context, AttributeSet attributeSet) {
        super(context, attributeSet, 0);
        setClipChildren(false);
        setClipToPadding(false);
        ViewOnAttachStateChangeListenerC0068e viewOnAttachStateChangeListenerC0068e = new ViewOnAttachStateChangeListenerC0068e(this, 3);
        addOnAttachStateChangeListener(viewOnAttachStateChangeListenerC0068e);
        U0 listener = new U0(this);
        Intrinsics.checkNotNullParameter(this, "<this>");
        Intrinsics.checkNotNullParameter(listener, "listener");
        androidx.customview.poolingcontainer.a aVarC = G6.c(this);
        Intrinsics.checkNotNullParameter(listener, "listener");
        aVarC.a.add(listener);
        this.disposeViewCompositionStrategy = new C0473q(this, viewOnAttachStateChangeListenerC0068e, listener, 12);
    }

    @Override // android.view.ViewGroup
    public void addView(View view, int i) {
        a();
        super.addView(view, i);
    }

    @Override // android.view.ViewGroup
    public boolean addViewInLayout(View view, int i, ViewGroup.LayoutParams layoutParams, boolean z) {
        a();
        return super.addViewInLayout(view, i, layoutParams, z);
    }

    @Override // android.view.ViewGroup
    public void addView(View view, int i, int i2) {
        a();
        super.addView(view, i, i2);
    }

    @Override // android.view.ViewGroup, android.view.ViewManager
    public void addView(View view, ViewGroup.LayoutParams layoutParams) {
        a();
        super.addView(view, layoutParams);
    }

    @Override // android.view.ViewGroup
    public void addView(View view, int i, ViewGroup.LayoutParams layoutParams) {
        a();
        super.addView(view, i, layoutParams);
    }
}
