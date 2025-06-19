package androidx.compose.ui.platform;

import android.content.Context;
import android.content.res.Configuration;
import android.graphics.Canvas;
import android.graphics.Point;
import android.graphics.Rect;
import android.os.Build;
import android.os.Trace;
import android.util.LongSparseArray;
import android.util.SparseArray;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.ViewStructure;
import android.view.ViewTreeObserver;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.animation.AnimationUtils;
import android.view.autofill.AutofillId;
import android.view.autofill.AutofillValue;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import androidx.activity.RunnableC0041m;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.camera2.internal.C0132i;
import androidx.compose.animation.C0281h;
import androidx.compose.animation.core.C0242g;
import androidx.compose.material3.C0634i2;
import androidx.compose.runtime.C0775b0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.graphics.C0847g;
import androidx.compose.ui.graphics.C0859t;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.AbstractC0918n;
import androidx.compose.ui.node.C0923t;
import androidx.compose.ui.semantics.EmptySemanticsElement;
import androidx.compose.ui.text.font.InterfaceC0994h;
import androidx.lifecycle.InterfaceC1250k;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3258s5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3307y6;
import com.google.android.gms.internal.mlkit_vision_barcode.K5;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import kotlin.InterfaceC4935d;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: androidx.compose.ui.platform.v, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0971v extends ViewGroup implements androidx.compose.ui.node.g0, androidx.compose.ui.node.m0, InterfaceC1250k {
    public static Class J1;
    public static Method K1;
    public final C0942g A;
    public final androidx.compose.runtime.collection.b A1;
    public final androidx.compose.ui.node.i0 B;
    public final androidx.appcompat.app.J B1;
    public boolean C;
    public final RunnableC0041m C1;
    public C0941f0 D;
    public boolean D1;
    public C0964r0 E;
    public final C0965s E1;
    public androidx.compose.ui.unit.a F;
    public final InterfaceC0945h0 F1;
    public boolean G;
    public boolean G1;
    public final androidx.compose.ui.node.S H;
    public final androidx.compose.ui.scrollcapture.l H1;
    public final C0937d0 I;
    public final r I1;
    public long J;
    public final int[] K;
    public final float[] L;
    public final float[] M;
    public final float[] V;
    public long W;
    public long a;
    public final boolean b;
    public final androidx.compose.ui.node.G c;
    public boolean c1;
    public final InterfaceC0773a0 d;
    public long d1;
    public final androidx.compose.ui.focus.j e;
    public boolean e1;
    public CoroutineContext f;
    public final InterfaceC0773a0 f1;
    public final ViewOnDragListenerC0963q0 g;
    public final androidx.compose.runtime.E g1;
    public final f1 h;
    public Function1 h1;
    public final C0859t i;
    public final ViewTreeObserverOnGlobalLayoutListenerC0944h i1;
    public final androidx.compose.ui.node.E j;
    public final ViewTreeObserverOnScrollChangedListenerC0946i j1;
    public final C0971v k;
    public final ViewTreeObserverOnTouchModeChangeListenerC0948j k1;
    public final androidx.compose.ui.semantics.p l;
    public final androidx.compose.ui.text.input.E l1;
    public final F m;
    public final androidx.compose.ui.text.input.B m1;
    public androidx.compose.ui.contentcapture.c n;
    public final AtomicReference n1;
    public final C0940f o;
    public final C0957n0 o1;
    public final C0847g p;
    public final S p1;
    public final androidx.compose.ui.autofill.f q;
    public final InterfaceC0773a0 q1;
    public final ArrayList r;
    public int r1;
    public ArrayList s;
    public final InterfaceC0773a0 s1;
    public boolean t;
    public final androidx.compose.ui.hapticfeedback.b t1;
    public boolean u;
    public final androidx.compose.ui.input.c u1;
    public final androidx.compose.ui.input.pointer.c v;
    public final androidx.compose.ui.modifier.d v1;
    public final androidx.compose.material.ripple.r w;
    public final W w1;
    public Function1 x;
    public MotionEvent x1;
    public final androidx.compose.ui.autofill.a y;
    public long y1;
    public boolean z;
    public final androidx.work.impl.model.v z1;

    /* JADX WARN: Type inference failed for: r4v13, types: [androidx.compose.ui.platform.j] */
    public C0971v(Context context, CoroutineContext coroutineContext) {
        super(context);
        this.a = 9205357640488583168L;
        this.b = true;
        this.c = new androidx.compose.ui.node.G();
        androidx.compose.ui.unit.d dVarB = K5.b(context);
        androidx.compose.runtime.V v = androidx.compose.runtime.V.d;
        this.d = C0776c.y(dVarB, v);
        androidx.compose.ui.semantics.e eVar = new androidx.compose.ui.semantics.e();
        EmptySemanticsElement emptySemanticsElement = new EmptySemanticsElement(eVar);
        this.e = new androidx.compose.ui.focus.j(new androidx.compose.foundation.text.z0(1, this, C0971v.class, "registerOnEndApplyChangesListener", "registerOnEndApplyChangesListener(Lkotlin/jvm/functions/Function0;)V", 0, 1), new C0960p(2, this, C0971v.class, "onRequestFocusForOwner", "onRequestFocusForOwner-7o62pno(Landroidx/compose/ui/focus/FocusDirection;Landroidx/compose/ui/geometry/Rect;)Z", 0, 0), new androidx.compose.foundation.text.z0(1, this, C0971v.class, "onMoveFocusInChildren", "onMoveFocusInChildren-3ESFkO8(I)Z", 0, 2), new androidx.activity.K(0, this, C0971v.class, "onClearFocusForOwner", "onClearFocusForOwner()V", 0, 7), new androidx.activity.K(0, this, C0971v.class, "onFetchFocusRect", "onFetchFocusRect()Landroidx/compose/ui/geometry/Rect;", 0, 8), new androidx.compose.material3.internal.O(0, 1, C0971v.class, this, "layoutDirection", "getLayoutDirection()Landroidx/compose/ui/unit/LayoutDirection;"));
        ViewOnDragListenerC0963q0 viewOnDragListenerC0963q0 = new ViewOnDragListenerC0963q0();
        this.f = coroutineContext;
        this.g = viewOnDragListenerC0963q0;
        this.h = new f1();
        androidx.compose.ui.q qVarD = androidx.compose.ui.input.key.c.d(androidx.compose.ui.n.b, new C0952l(this, 1));
        androidx.compose.ui.q qVarA = androidx.compose.ui.input.rotary.a.a();
        this.i = new C0859t();
        androidx.compose.ui.node.E e = new androidx.compose.ui.node.E(3);
        e.Y(androidx.compose.ui.layout.Z.b);
        e.W(getDensity());
        e.Z(emptySemanticsElement.g(qVarA).g(qVarD).g(((androidx.compose.ui.focus.j) getFocusOwner()).i).g(viewOnDragListenerC0963q0.c));
        this.j = e;
        this.k = this;
        this.l = new androidx.compose.ui.semantics.p(getRoot(), eVar);
        F f = new F(this);
        this.m = f;
        this.n = new androidx.compose.ui.contentcapture.c(this, new androidx.activity.K(0, this, N.class, "getContentCaptureSessionCompat", "getContentCaptureSessionCompat(Landroid/view/View;)Landroidx/compose/ui/platform/coreshims/ContentCaptureSessionCompat;", 1, 6));
        this.o = new C0940f(context);
        this.p = new C0847g(this);
        this.q = new androidx.compose.ui.autofill.f();
        this.r = new ArrayList();
        this.v = new androidx.compose.ui.input.pointer.c();
        androidx.compose.ui.node.E root = getRoot();
        androidx.compose.material.ripple.r rVar = new androidx.compose.material.ripple.r();
        rVar.b = root;
        rVar.c = new com.quizlet.data.repository.folderwithcreator.e((C0923t) root.w.c);
        rVar.d = new com.airbnb.lottie.network.c(9);
        rVar.e = new androidx.compose.ui.node.r();
        this.w = rVar;
        this.x = C0956n.b;
        this.y = new androidx.compose.ui.autofill.a(this, getAutofillTree());
        this.A = new C0942g(context);
        this.B = new androidx.compose.ui.node.i0(new C0952l(this, 2));
        this.H = new androidx.compose.ui.node.S(getRoot());
        this.I = new C0937d0(ViewConfiguration.get(context));
        this.J = P5.b(SubsamplingScaleImageView.TILE_SIZE_AUTO, SubsamplingScaleImageView.TILE_SIZE_AUTO);
        this.K = new int[]{0, 0};
        float[] fArrA = androidx.compose.ui.graphics.J.a();
        this.L = fArrA;
        this.M = androidx.compose.ui.graphics.J.a();
        this.V = androidx.compose.ui.graphics.J.a();
        this.W = -1L;
        this.d1 = 9187343241974906880L;
        this.e1 = true;
        this.f1 = C0776c.z(null);
        this.g1 = C0776c.q(new C0965s(this, 1));
        this.i1 = new ViewTreeObserverOnGlobalLayoutListenerC0944h(this, 0);
        this.j1 = new ViewTreeObserverOnScrollChangedListenerC0946i(this, 0);
        this.k1 = new ViewTreeObserver.OnTouchModeChangeListener() { // from class: androidx.compose.ui.platform.j
            @Override // android.view.ViewTreeObserver.OnTouchModeChangeListener
            public final void onTouchModeChanged(boolean z) {
                ((androidx.compose.runtime.L0) this.a.u1.a).setValue(new androidx.compose.ui.input.a(z ? 1 : 2));
            }
        };
        androidx.compose.ui.text.input.E e2 = new androidx.compose.ui.text.input.E(getView(), this);
        this.l1 = e2;
        this.m1 = new androidx.compose.ui.text.input.B(e2);
        this.n1 = new AtomicReference(null);
        this.o1 = new C0957n0(getTextInputService());
        this.p1 = new S(context);
        this.q1 = C0776c.y(AbstractC3258s5.c(context), v);
        Configuration configuration = context.getResources().getConfiguration();
        int i = Build.VERSION.SDK_INT;
        this.r1 = i >= 31 ? configuration.fontWeightAdjustment : 0;
        int layoutDirection = context.getResources().getConfiguration().getLayoutDirection();
        androidx.compose.ui.unit.k kVar = androidx.compose.ui.unit.k.a;
        androidx.compose.ui.unit.k kVar2 = layoutDirection != 0 ? layoutDirection != 1 ? null : androidx.compose.ui.unit.k.b : kVar;
        this.s1 = C0776c.z(kVar2 != null ? kVar2 : kVar);
        this.t1 = new androidx.compose.ui.hapticfeedback.b(this);
        this.u1 = new androidx.compose.ui.input.c(isInTouchMode() ? 1 : 2, new C0952l(this, 0));
        this.v1 = new androidx.compose.ui.modifier.d(this);
        this.w1 = new W(this);
        this.z1 = new androidx.work.impl.model.v(4);
        this.A1 = new androidx.compose.runtime.collection.b(new Function0[16]);
        this.B1 = new androidx.appcompat.app.J(this, 7);
        this.C1 = new RunnableC0041m(this, 28);
        this.E1 = new C0965s(this, 0);
        this.F1 = i < 29 ? new androidx.work.impl.model.l(fArrA) : new C0947i0();
        addOnAttachStateChangeListener(this.n);
        setWillNotDraw(false);
        setFocusable(true);
        M.a.a(this, 1, false);
        setFocusableInTouchMode(true);
        setClipChildren(false);
        androidx.core.view.V.o(this, f);
        setOnDragListener(viewOnDragListenerC0963q0);
        getRoot().e(this);
        if (i >= 29) {
            H.a.a(this);
        }
        this.H1 = i >= 31 ? new androidx.compose.ui.scrollcapture.l() : null;
        this.I1 = new r(this);
    }

    public static final void a(C0971v c0971v, int i, AccessibilityNodeInfo accessibilityNodeInfo, String str) {
        int iD;
        F f = c0971v.m;
        if (Intrinsics.b(str, f.E)) {
            int iD2 = f.C.d(i);
            if (iD2 != -1) {
                accessibilityNodeInfo.getExtras().putInt(str, iD2);
                return;
            }
            return;
        }
        if (!Intrinsics.b(str, f.F) || (iD = f.D.d(i)) == -1) {
            return;
        }
        accessibilityNodeInfo.getExtras().putInt(str, iD);
    }

    public static final boolean e(C0971v c0971v, androidx.compose.ui.focus.c cVar, androidx.compose.ui.geometry.c cVar2) {
        Integer numM;
        if (c0971v.isFocused() || c0971v.hasFocus()) {
            return true;
        }
        return super.requestFocus((cVar == null || (numM = androidx.compose.ui.focus.a.M(cVar.a)) == null) ? 130 : numM.intValue(), cVar2 != null ? androidx.compose.ui.graphics.F.w(cVar2) : null);
    }

    public static void f(ViewGroup viewGroup) {
        int childCount = viewGroup.getChildCount();
        for (int i = 0; i < childCount; i++) {
            View childAt = viewGroup.getChildAt(i);
            if (childAt instanceof C0971v) {
                ((C0971v) childAt).t();
            } else if (childAt instanceof ViewGroup) {
                f((ViewGroup) childAt);
            }
        }
    }

    public static long g(int i) {
        int mode = View.MeasureSpec.getMode(i);
        int size = View.MeasureSpec.getSize(i);
        if (mode == Integer.MIN_VALUE) {
            kotlin.C c = kotlin.D.b;
            return (0 << 32) | size;
        }
        if (mode == 0) {
            kotlin.C c2 = kotlin.D.b;
            return (0 << 32) | SubsamplingScaleImageView.TILE_SIZE_AUTO;
        }
        if (mode != 1073741824) {
            throw new IllegalStateException();
        }
        long j = size;
        kotlin.C c3 = kotlin.D.b;
        return (j << 32) | j;
    }

    @InterfaceC4935d
    public static /* synthetic */ void getFontLoader$annotations() {
    }

    public static /* synthetic */ void getLastMatrixRecalculationAnimationTime$ui_release$annotations() {
    }

    public static /* synthetic */ void getShowLayoutBounds$annotations() {
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final C0950k get_viewTreeOwners() {
        return (C0950k) ((androidx.compose.runtime.L0) this.f1).getValue();
    }

    public static View i(int i, View view) throws NoSuchMethodException, SecurityException {
        if (Build.VERSION.SDK_INT < 29) {
            Method declaredMethod = View.class.getDeclaredMethod("getAccessibilityViewId", null);
            declaredMethod.setAccessible(true);
            if (Intrinsics.b(declaredMethod.invoke(view, null), Integer.valueOf(i))) {
                return view;
            }
            if (view instanceof ViewGroup) {
                ViewGroup viewGroup = (ViewGroup) view;
                int childCount = viewGroup.getChildCount();
                for (int i2 = 0; i2 < childCount; i2++) {
                    View viewI = i(i, viewGroup.getChildAt(i2));
                    if (viewI != null) {
                        return viewI;
                    }
                }
            }
        }
        return null;
    }

    public static void k(androidx.compose.ui.node.E e) {
        e.A();
        androidx.compose.runtime.collection.b bVarW = e.w();
        int i = bVarW.c;
        if (i > 0) {
            Object[] objArr = bVarW.a;
            int i2 = 0;
            do {
                k((androidx.compose.ui.node.E) objArr[i2]);
                i2++;
            } while (i2 < i);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0044  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x007f  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0082 A[LOOP:0: B:22:0x004c->B:39:0x0082, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0085 A[EDGE_INSN: B:41:0x0085->B:40:0x0085 BREAK  A[LOOP:0: B:22:0x004c->B:39:0x0082], SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean m(android.view.MotionEvent r6) {
        /*
            float r0 = r6.getX()
            boolean r1 = java.lang.Float.isInfinite(r0)
            r2 = 0
            r3 = 1
            if (r1 != 0) goto L44
            boolean r0 = java.lang.Float.isNaN(r0)
            if (r0 != 0) goto L44
            float r0 = r6.getY()
            boolean r1 = java.lang.Float.isInfinite(r0)
            if (r1 != 0) goto L44
            boolean r0 = java.lang.Float.isNaN(r0)
            if (r0 != 0) goto L44
            float r0 = r6.getRawX()
            boolean r1 = java.lang.Float.isInfinite(r0)
            if (r1 != 0) goto L44
            boolean r0 = java.lang.Float.isNaN(r0)
            if (r0 != 0) goto L44
            float r0 = r6.getRawY()
            boolean r1 = java.lang.Float.isInfinite(r0)
            if (r1 != 0) goto L44
            boolean r0 = java.lang.Float.isNaN(r0)
            if (r0 != 0) goto L44
            r0 = r2
            goto L45
        L44:
            r0 = r3
        L45:
            if (r0 != 0) goto L85
            int r1 = r6.getPointerCount()
            r4 = r3
        L4c:
            if (r4 >= r1) goto L85
            float r0 = r6.getX(r4)
            boolean r5 = java.lang.Float.isInfinite(r0)
            if (r5 != 0) goto L7f
            boolean r0 = java.lang.Float.isNaN(r0)
            if (r0 != 0) goto L7f
            float r0 = r6.getY(r4)
            boolean r5 = java.lang.Float.isInfinite(r0)
            if (r5 != 0) goto L7f
            boolean r0 = java.lang.Float.isNaN(r0)
            if (r0 != 0) goto L7f
            int r0 = android.os.Build.VERSION.SDK_INT
            r5 = 29
            if (r0 < r5) goto L7d
            androidx.compose.ui.platform.A0 r0 = androidx.compose.ui.platform.A0.a
            boolean r0 = r0.a(r6, r4)
            if (r0 != 0) goto L7d
            goto L7f
        L7d:
            r0 = r2
            goto L80
        L7f:
            r0 = r3
        L80:
            if (r0 != 0) goto L85
            int r4 = r4 + 1
            goto L4c
        L85:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.C0971v.m(android.view.MotionEvent):boolean");
    }

    private void setDensity(androidx.compose.ui.unit.b bVar) {
        ((androidx.compose.runtime.L0) this.d).setValue(bVar);
    }

    private void setFontFamilyResolver(androidx.compose.ui.text.font.i iVar) {
        ((androidx.compose.runtime.L0) this.q1).setValue(iVar);
    }

    private void setLayoutDirection(androidx.compose.ui.unit.k kVar) {
        ((androidx.compose.runtime.L0) this.s1).setValue(kVar);
    }

    private final void set_viewTreeOwners(C0950k c0950k) {
        ((androidx.compose.runtime.L0) this.f1).setValue(c0950k);
    }

    public final void A(androidx.compose.ui.node.f0 f0Var) {
        androidx.work.impl.model.v vVar;
        Reference referencePoll;
        androidx.compose.runtime.collection.b bVar;
        if (this.E != null) {
            C0634i2 c0634i2 = a1.p;
        }
        do {
            vVar = this.z1;
            referencePoll = ((ReferenceQueue) vVar.c).poll();
            bVar = (androidx.compose.runtime.collection.b) vVar.b;
            if (referencePoll != null) {
                bVar.n(referencePoll);
            }
        } while (referencePoll != null);
        bVar.b(new WeakReference(f0Var, (ReferenceQueue) vVar.c));
    }

    public final void B(androidx.compose.ui.node.E e) {
        if (isLayoutRequested() || !isAttachedToWindow()) {
            return;
        }
        if (e != null) {
            while (e != null && e.x.r.k == 1) {
                if (!this.G) {
                    androidx.compose.ui.node.E eS = e.s();
                    if (eS == null) {
                        break;
                    }
                    long j = ((C0923t) eS.w.c).d;
                    if (androidx.compose.ui.unit.a.f(j) && androidx.compose.ui.unit.a.e(j)) {
                        break;
                    }
                }
                e = e.s();
            }
            if (e == getRoot()) {
                requestLayout();
                return;
            }
        }
        if (getWidth() == 0 || getHeight() == 0) {
            requestLayout();
        } else {
            invalidate();
        }
    }

    public final long C(long j) {
        z();
        float fD = androidx.compose.ui.geometry.b.d(j) - androidx.compose.ui.geometry.b.d(this.d1);
        float fE = androidx.compose.ui.geometry.b.e(j) - androidx.compose.ui.geometry.b.e(this.d1);
        return androidx.compose.ui.graphics.J.b(Q4.c(fD, fE), this.V);
    }

    public final int D(MotionEvent motionEvent) {
        Object obj;
        if (this.G1) {
            this.G1 = false;
            int metaState = motionEvent.getMetaState();
            this.h.getClass();
            ((androidx.compose.runtime.L0) f1.b).setValue(new androidx.compose.ui.input.pointer.t(metaState));
        }
        androidx.compose.ui.input.pointer.c cVar = this.v;
        com.quizlet.data.repository.qclass.c cVarA = cVar.a(motionEvent, this);
        androidx.compose.material.ripple.r rVar = this.w;
        if (cVarA == null) {
            rVar.l();
            return 0;
        }
        ArrayList arrayList = (ArrayList) cVarA.b;
        int size = arrayList.size() - 1;
        if (size >= 0) {
            while (true) {
                int i = size - 1;
                obj = arrayList.get(size);
                if (((androidx.compose.ui.input.pointer.p) obj).e) {
                    break;
                }
                if (i < 0) {
                    break;
                }
                size = i;
            }
            obj = null;
        } else {
            obj = null;
        }
        androidx.compose.ui.input.pointer.p pVar = (androidx.compose.ui.input.pointer.p) obj;
        if (pVar != null) {
            this.a = pVar.d;
        }
        int iK = rVar.k(cVarA, this, n(motionEvent));
        int actionMasked = motionEvent.getActionMasked();
        if ((actionMasked != 0 && actionMasked != 5) || (iK & 1) != 0) {
            return iK;
        }
        int pointerId = motionEvent.getPointerId(motionEvent.getActionIndex());
        cVar.c.delete(pointerId);
        cVar.b.delete(pointerId);
        return iK;
    }

    public final void E(MotionEvent motionEvent, int i, long j, boolean z) {
        int actionMasked = motionEvent.getActionMasked();
        int actionIndex = -1;
        if (actionMasked != 1) {
            if (actionMasked == 6) {
                actionIndex = motionEvent.getActionIndex();
            }
        } else if (i != 9 && i != 10) {
            actionIndex = 0;
        }
        int pointerCount = motionEvent.getPointerCount() - (actionIndex >= 0 ? 1 : 0);
        if (pointerCount == 0) {
            return;
        }
        MotionEvent.PointerProperties[] pointerPropertiesArr = new MotionEvent.PointerProperties[pointerCount];
        for (int i2 = 0; i2 < pointerCount; i2++) {
            pointerPropertiesArr[i2] = new MotionEvent.PointerProperties();
        }
        MotionEvent.PointerCoords[] pointerCoordsArr = new MotionEvent.PointerCoords[pointerCount];
        for (int i3 = 0; i3 < pointerCount; i3++) {
            pointerCoordsArr[i3] = new MotionEvent.PointerCoords();
        }
        int i4 = 0;
        while (i4 < pointerCount) {
            int i5 = ((actionIndex < 0 || i4 < actionIndex) ? 0 : 1) + i4;
            motionEvent.getPointerProperties(i5, pointerPropertiesArr[i4]);
            MotionEvent.PointerCoords pointerCoords = pointerCoordsArr[i4];
            motionEvent.getPointerCoords(i5, pointerCoords);
            long jP = p(Q4.c(pointerCoords.x, pointerCoords.y));
            pointerCoords.x = androidx.compose.ui.geometry.b.d(jP);
            pointerCoords.y = androidx.compose.ui.geometry.b.e(jP);
            i4++;
        }
        MotionEvent motionEventObtain = MotionEvent.obtain(motionEvent.getDownTime() == motionEvent.getEventTime() ? j : motionEvent.getDownTime(), j, i, pointerCount, pointerPropertiesArr, pointerCoordsArr, motionEvent.getMetaState(), z ? 0 : motionEvent.getButtonState(), motionEvent.getXPrecision(), motionEvent.getYPrecision(), motionEvent.getDeviceId(), motionEvent.getEdgeFlags(), motionEvent.getSource(), motionEvent.getFlags());
        com.quizlet.data.repository.qclass.c cVarA = this.v.a(motionEventObtain, this);
        Intrinsics.d(cVarA);
        this.w.k(cVarA, this, true);
        motionEventObtain.recycle();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void F(androidx.compose.foundation.text.input.internal.C0500f r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r5 = this;
            boolean r0 = r7 instanceof androidx.compose.ui.platform.C0969u
            if (r0 == 0) goto L13
            r0 = r7
            androidx.compose.ui.platform.u r0 = (androidx.compose.ui.platform.C0969u) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            androidx.compose.ui.platform.u r0 = new androidx.compose.ui.platform.u
            r0.<init>(r5, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 == r3) goto L2b
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L2b:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L49
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.util.concurrent.atomic.AtomicReference r7 = r5.n1
            androidx.compose.ui.platform.l r2 = new androidx.compose.ui.platform.l
            r4 = 3
            r2.<init>(r5, r4)
            r0.l = r3
            androidx.compose.ui.t r3 = new androidx.compose.ui.t
            r4 = 0
            r3.<init>(r2, r7, r6, r4)
            java.lang.Object r6 = kotlinx.coroutines.E.m(r3, r0)
            if (r6 != r1) goto L49
            return
        L49:
            kotlin.KotlinNothingValueException r6 = new kotlin.KotlinNothingValueException
            r6.<init>()
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.C0971v.F(androidx.compose.foundation.text.input.internal.f, kotlin.coroutines.jvm.internal.c):void");
    }

    public final void G() {
        int[] iArr = this.K;
        getLocationOnScreen(iArr);
        long j = this.J;
        int i = (int) (j >> 32);
        int i2 = (int) (j & 4294967295L);
        boolean z = false;
        int i3 = iArr[0];
        if (i != i3 || i2 != iArr[1]) {
            this.J = P5.b(i3, iArr[1]);
            if (i != Integer.MAX_VALUE && i2 != Integer.MAX_VALUE) {
                getRoot().x.r.C0();
                z = true;
            }
        }
        this.H.a(z);
    }

    @Override // android.view.ViewGroup
    public final void addView(View view) {
        addView(view, -1);
    }

    @Override // android.view.View
    public final void autofill(SparseArray sparseArray) {
        androidx.compose.ui.autofill.a aVar = this.y;
        if (aVar != null) {
            int size = sparseArray.size();
            for (int i = 0; i < size; i++) {
                int iKeyAt = sparseArray.keyAt(i);
                AutofillValue autofillValue = (AutofillValue) sparseArray.get(iKeyAt);
                androidx.compose.ui.autofill.d dVar = androidx.compose.ui.autofill.d.a;
                if (dVar.d(autofillValue)) {
                    dVar.i(autofillValue).toString();
                    if (aVar.b.a.get(Integer.valueOf(iKeyAt)) != null) {
                        throw new ClassCastException();
                    }
                } else {
                    if (dVar.b(autofillValue)) {
                        Intrinsics.checkNotNullParameter("An operation is not implemented: b/138604541: Add onFill() callback for date", "message");
                        throw new kotlin.n("An operation is not implemented: b/138604541: Add onFill() callback for date");
                    }
                    if (dVar.c(autofillValue)) {
                        Intrinsics.checkNotNullParameter("An operation is not implemented: b/138604541: Add onFill() callback for list", "message");
                        throw new kotlin.n("An operation is not implemented: b/138604541: Add onFill() callback for list");
                    }
                    if (dVar.e(autofillValue)) {
                        Intrinsics.checkNotNullParameter("An operation is not implemented: b/138604541:  Add onFill() callback for toggle", "message");
                        throw new kotlin.n("An operation is not implemented: b/138604541:  Add onFill() callback for toggle");
                    }
                }
            }
        }
    }

    @Override // android.view.View
    public final boolean canScrollHorizontally(int i) {
        return this.m.m(false, this.a, i);
    }

    @Override // android.view.View
    public final boolean canScrollVertically(int i) {
        return this.m.m(true, this.a, i);
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0023  */
    @Override // android.view.ViewGroup, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void dispatchDraw(android.graphics.Canvas r7) {
        /*
            r6 = this;
            boolean r0 = r6.isAttachedToWindow()
            if (r0 != 0) goto Ld
            androidx.compose.ui.node.E r0 = r6.getRoot()
            k(r0)
        Ld:
            r0 = 1
            r6.q(r0)
            java.lang.Object r1 = androidx.compose.runtime.snapshots.m.b
            monitor-enter(r1)
            androidx.compose.runtime.snapshots.c r2 = androidx.compose.runtime.snapshots.m.i     // Catch: java.lang.Throwable -> L25
            androidx.collection.J r2 = r2.h     // Catch: java.lang.Throwable -> L25
            r3 = 0
            if (r2 == 0) goto L23
            boolean r2 = r2.h()     // Catch: java.lang.Throwable -> L25
            if (r2 != r0) goto L23
            r2 = r0
            goto L27
        L23:
            r2 = r3
            goto L27
        L25:
            r7 = move-exception
            goto L88
        L27:
            monitor-exit(r1)
            if (r2 == 0) goto L2d
            androidx.compose.runtime.snapshots.m.a()
        L2d:
            r6.t = r0
            androidx.compose.ui.graphics.t r0 = r6.i
            androidx.compose.ui.graphics.d r1 = r0.a
            android.graphics.Canvas r2 = r1.a
            r1.a = r7
            androidx.compose.ui.node.E r4 = r6.getRoot()
            r5 = 0
            r4.j(r1, r5)
            androidx.compose.ui.graphics.d r0 = r0.a
            r0.a = r2
            java.util.ArrayList r0 = r6.r
            boolean r0 = r0.isEmpty()
            if (r0 != 0) goto L62
            java.util.ArrayList r0 = r6.r
            int r0 = r0.size()
            r1 = r3
        L52:
            if (r1 >= r0) goto L62
            java.util.ArrayList r2 = r6.r
            java.lang.Object r2 = r2.get(r1)
            androidx.compose.ui.node.f0 r2 = (androidx.compose.ui.node.f0) r2
            r2.k()
            int r1 = r1 + 1
            goto L52
        L62:
            boolean r0 = androidx.compose.ui.platform.a1.t
            if (r0 == 0) goto L74
            int r0 = r7.save()
            r1 = 0
            r7.clipRect(r1, r1, r1, r1)
            super.dispatchDraw(r7)
            r7.restoreToCount(r0)
        L74:
            java.util.ArrayList r7 = r6.r
            r7.clear()
            r6.t = r3
            java.util.ArrayList r7 = r6.s
            if (r7 == 0) goto L87
            java.util.ArrayList r0 = r6.r
            r0.addAll(r7)
            r7.clear()
        L87:
            return
        L88:
            monitor-exit(r1)
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.C0971v.dispatchDraw(android.graphics.Canvas):void");
    }

    @Override // android.view.View
    public final boolean dispatchGenericMotionEvent(MotionEvent motionEvent) {
        androidx.compose.ui.input.rotary.b bVar;
        int size;
        androidx.compose.ui.node.V v;
        androidx.compose.ui.p pVarF;
        androidx.compose.ui.node.V v2;
        if (this.D1) {
            RunnableC0041m runnableC0041m = this.C1;
            removeCallbacks(runnableC0041m);
            if (motionEvent.getActionMasked() == 8) {
                this.D1 = false;
            } else {
                runnableC0041m.run();
            }
        }
        if (motionEvent.getActionMasked() != 8) {
            return super.dispatchGenericMotionEvent(motionEvent);
        }
        if (m(motionEvent) || !isAttachedToWindow()) {
            return super.dispatchGenericMotionEvent(motionEvent);
        }
        if (!motionEvent.isFromSource(4194304)) {
            return (j(motionEvent) & 1) != 0;
        }
        ViewConfiguration viewConfiguration = ViewConfiguration.get(getContext());
        motionEvent.getAxisValue(26);
        getContext();
        viewConfiguration.getScaledVerticalScrollFactor();
        getContext();
        viewConfiguration.getScaledHorizontalScrollFactor();
        motionEvent.getEventTime();
        motionEvent.getDeviceId();
        androidx.compose.ui.focus.j jVar = (androidx.compose.ui.focus.j) getFocusOwner();
        if (jVar.g.a()) {
            throw new IllegalStateException("Dispatching rotary event while focus system is invalidated.");
        }
        androidx.compose.ui.focus.t tVarG = androidx.compose.ui.focus.a.g(jVar.f);
        if (tVarG != null) {
            androidx.compose.ui.p pVar = tVarG.a;
            if (!pVar.m) {
                throw new IllegalStateException("visitAncestors called on an unattached node");
            }
            androidx.compose.ui.node.E eV = AbstractC0910f.v(tVarG);
            loop0: while (true) {
                if (eV == null) {
                    pVarF = null;
                    break;
                }
                if ((((androidx.compose.ui.p) eV.w.f).d & 16384) != 0) {
                    while (pVar != null) {
                        if ((pVar.c & 16384) != 0) {
                            androidx.compose.runtime.collection.b bVar2 = null;
                            pVarF = pVar;
                            while (pVarF != null) {
                                if (pVarF instanceof androidx.compose.ui.input.rotary.b) {
                                    break loop0;
                                }
                                if ((pVarF.c & 16384) != 0 && (pVarF instanceof AbstractC0918n)) {
                                    int i = 0;
                                    for (androidx.compose.ui.p pVar2 = ((AbstractC0918n) pVarF).o; pVar2 != null; pVar2 = pVar2.f) {
                                        if ((pVar2.c & 16384) != 0) {
                                            i++;
                                            if (i == 1) {
                                                pVarF = pVar2;
                                            } else {
                                                if (bVar2 == null) {
                                                    bVar2 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                                }
                                                if (pVarF != null) {
                                                    bVar2.b(pVarF);
                                                    pVarF = null;
                                                }
                                                bVar2.b(pVar2);
                                            }
                                        }
                                    }
                                    if (i == 1) {
                                    }
                                }
                                pVarF = AbstractC0910f.f(bVar2);
                            }
                        }
                        pVar = pVar.e;
                    }
                }
                eV = eV.s();
                pVar = (eV == null || (v2 = eV.w) == null) ? null : (androidx.compose.ui.node.o0) v2.e;
            }
            bVar = (androidx.compose.ui.input.rotary.b) pVarF;
        } else {
            bVar = null;
        }
        if (bVar != null) {
            androidx.compose.ui.input.rotary.b bVar3 = bVar;
            androidx.compose.ui.p pVar3 = bVar3.a;
            if (!pVar3.m) {
                throw new IllegalStateException("visitAncestors called on an unattached node");
            }
            androidx.compose.ui.p pVar4 = pVar3.e;
            androidx.compose.ui.node.E eV2 = AbstractC0910f.v(bVar);
            ArrayList arrayList = null;
            while (eV2 != null) {
                if ((((androidx.compose.ui.p) eV2.w.f).d & 16384) != 0) {
                    while (pVar4 != null) {
                        if ((pVar4.c & 16384) != 0) {
                            androidx.compose.ui.p pVarF2 = pVar4;
                            androidx.compose.runtime.collection.b bVar4 = null;
                            while (pVarF2 != null) {
                                if (pVarF2 instanceof androidx.compose.ui.input.rotary.b) {
                                    if (arrayList == null) {
                                        arrayList = new ArrayList();
                                    }
                                    arrayList.add(pVarF2);
                                } else if ((pVarF2.c & 16384) != 0 && (pVarF2 instanceof AbstractC0918n)) {
                                    int i2 = 0;
                                    for (androidx.compose.ui.p pVar5 = ((AbstractC0918n) pVarF2).o; pVar5 != null; pVar5 = pVar5.f) {
                                        if ((pVar5.c & 16384) != 0) {
                                            i2++;
                                            if (i2 == 1) {
                                                pVarF2 = pVar5;
                                            } else {
                                                if (bVar4 == null) {
                                                    bVar4 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                                }
                                                if (pVarF2 != null) {
                                                    bVar4.b(pVarF2);
                                                    pVarF2 = null;
                                                }
                                                bVar4.b(pVar5);
                                            }
                                        }
                                    }
                                    if (i2 == 1) {
                                    }
                                }
                                pVarF2 = AbstractC0910f.f(bVar4);
                            }
                        }
                        pVar4 = pVar4.e;
                    }
                }
                eV2 = eV2.s();
                pVar4 = (eV2 == null || (v = eV2.w) == null) ? null : (androidx.compose.ui.node.o0) v.e;
            }
            if (arrayList != null && arrayList.size() - 1 >= 0) {
                while (true) {
                    int i3 = size - 1;
                    ((androidx.compose.ui.input.rotary.b) arrayList.get(size)).getClass();
                    if (i3 < 0) {
                        break;
                    }
                    size = i3;
                }
            }
            androidx.compose.ui.p pVarF3 = bVar3.a;
            androidx.compose.runtime.collection.b bVar5 = null;
            while (pVarF3 != null) {
                if (pVarF3 instanceof androidx.compose.ui.input.rotary.b) {
                } else if ((pVarF3.c & 16384) != 0 && (pVarF3 instanceof AbstractC0918n)) {
                    int i4 = 0;
                    for (androidx.compose.ui.p pVar6 = ((AbstractC0918n) pVarF3).o; pVar6 != null; pVar6 = pVar6.f) {
                        if ((pVar6.c & 16384) != 0) {
                            i4++;
                            if (i4 == 1) {
                                pVarF3 = pVar6;
                            } else {
                                if (bVar5 == null) {
                                    bVar5 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                }
                                if (pVarF3 != null) {
                                    bVar5.b(pVarF3);
                                    pVarF3 = null;
                                }
                                bVar5.b(pVar6);
                            }
                        }
                    }
                    if (i4 == 1) {
                    }
                }
                pVarF3 = AbstractC0910f.f(bVar5);
            }
            androidx.compose.ui.p pVarF4 = bVar3.a;
            androidx.compose.runtime.collection.b bVar6 = null;
            while (pVarF4 != null) {
                if (pVarF4 instanceof androidx.compose.ui.input.rotary.b) {
                } else if ((pVarF4.c & 16384) != 0 && (pVarF4 instanceof AbstractC0918n)) {
                    int i5 = 0;
                    for (androidx.compose.ui.p pVar7 = ((AbstractC0918n) pVarF4).o; pVar7 != null; pVar7 = pVar7.f) {
                        if ((pVar7.c & 16384) != 0) {
                            i5++;
                            if (i5 == 1) {
                                pVarF4 = pVar7;
                            } else {
                                if (bVar6 == null) {
                                    bVar6 = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                }
                                if (pVarF4 != null) {
                                    bVar6.b(pVarF4);
                                    pVarF4 = null;
                                }
                                bVar6.b(pVar7);
                            }
                        }
                    }
                    if (i5 == 1) {
                    }
                }
                pVarF4 = AbstractC0910f.f(bVar6);
            }
            if (arrayList != null) {
                int size2 = arrayList.size();
                for (int i6 = 0; i6 < size2; i6++) {
                    C0956n c0956n = ((androidx.compose.ui.input.rotary.b) arrayList.get(i6)).n;
                }
            }
        }
        return false;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:68:0x0147 A[RETURN] */
    @Override // android.view.ViewGroup, android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean dispatchHoverEvent(android.view.MotionEvent r24) {
        /*
            Method dump skipped, instructions count: 329
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.C0971v.dispatchHoverEvent(android.view.MotionEvent):boolean");
    }

    @Override // android.view.ViewGroup, android.view.View
    public final boolean dispatchKeyEvent(KeyEvent keyEvent) {
        if (!isFocused()) {
            return ((androidx.compose.ui.focus.j) getFocusOwner()).c(keyEvent, new C0242g(23, this, keyEvent));
        }
        int metaState = keyEvent.getMetaState();
        this.h.getClass();
        ((androidx.compose.runtime.L0) f1.b).setValue(new androidx.compose.ui.input.pointer.t(metaState));
        return ((androidx.compose.ui.focus.j) getFocusOwner()).c(keyEvent, androidx.compose.ui.focus.g.b) || super.dispatchKeyEvent(keyEvent);
    }

    @Override // android.view.ViewGroup, android.view.View
    public final boolean dispatchKeyEventPreIme(KeyEvent keyEvent) {
        androidx.compose.ui.node.V v;
        if (isFocused()) {
            androidx.compose.ui.focus.j jVar = (androidx.compose.ui.focus.j) getFocusOwner();
            if (jVar.g.a()) {
                System.out.println((Object) "FocusRelatedWarning: Dispatching intercepted soft keyboard event while the focus system is invalidated.");
            } else {
                androidx.compose.ui.focus.t tVarG = androidx.compose.ui.focus.a.g(jVar.f);
                if (tVarG != null) {
                    androidx.compose.ui.p pVar = tVarG.a;
                    if (!pVar.m) {
                        throw new IllegalStateException("visitAncestors called on an unattached node");
                    }
                    androidx.compose.ui.node.E eV = AbstractC0910f.v(tVarG);
                    while (eV != null) {
                        if ((((androidx.compose.ui.p) eV.w.f).d & 131072) != 0) {
                            while (pVar != null) {
                                if ((pVar.c & 131072) != 0) {
                                    androidx.compose.ui.p pVarF = pVar;
                                    androidx.compose.runtime.collection.b bVar = null;
                                    while (pVarF != null) {
                                        if ((pVarF.c & 131072) != 0 && (pVarF instanceof AbstractC0918n)) {
                                            int i = 0;
                                            for (androidx.compose.ui.p pVar2 = ((AbstractC0918n) pVarF).o; pVar2 != null; pVar2 = pVar2.f) {
                                                if ((pVar2.c & 131072) != 0) {
                                                    i++;
                                                    if (i == 1) {
                                                        pVarF = pVar2;
                                                    } else {
                                                        if (bVar == null) {
                                                            bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                                        }
                                                        if (pVarF != null) {
                                                            bVar.b(pVarF);
                                                            pVarF = null;
                                                        }
                                                        bVar.b(pVar2);
                                                    }
                                                }
                                            }
                                            if (i == 1) {
                                            }
                                        }
                                        pVarF = AbstractC0910f.f(bVar);
                                    }
                                }
                                pVar = pVar.e;
                            }
                        }
                        eV = eV.s();
                        pVar = (eV == null || (v = eV.w) == null) ? null : (androidx.compose.ui.node.o0) v.e;
                    }
                }
            }
        }
        return super.dispatchKeyEventPreIme(keyEvent);
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void dispatchProvideStructure(ViewStructure viewStructure) {
        if (Build.VERSION.SDK_INT < 28) {
            G.a.a(viewStructure, getView());
        } else {
            super.dispatchProvideStructure(viewStructure);
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public final boolean dispatchTouchEvent(MotionEvent motionEvent) {
        if (this.D1) {
            RunnableC0041m runnableC0041m = this.C1;
            removeCallbacks(runnableC0041m);
            MotionEvent motionEvent2 = this.x1;
            Intrinsics.d(motionEvent2);
            if (motionEvent.getActionMasked() == 0 && motionEvent2.getSource() == motionEvent.getSource() && motionEvent2.getToolType(0) == motionEvent.getToolType(0)) {
                this.D1 = false;
            } else {
                runnableC0041m.run();
            }
        }
        if (!m(motionEvent) && isAttachedToWindow() && (motionEvent.getActionMasked() != 2 || o(motionEvent))) {
            int iJ = j(motionEvent);
            if ((iJ & 2) != 0) {
                getParent().requestDisallowInterceptTouchEvent(true);
            }
            if ((iJ & 1) != 0) {
                return true;
            }
        }
        return false;
    }

    public final View findViewByAccessibilityIdTraversal(int i) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        try {
            if (Build.VERSION.SDK_INT < 29) {
                return i(i, this);
            }
            Method declaredMethod = View.class.getDeclaredMethod("findViewByAccessibilityIdTraversal", Integer.TYPE);
            declaredMethod.setAccessible(true);
            Object objInvoke = declaredMethod.invoke(this, Integer.valueOf(i));
            if (objInvoke instanceof View) {
                return (View) objInvoke;
            }
            return null;
        } catch (NoSuchMethodException unused) {
            return null;
        }
    }

    @Override // android.view.ViewGroup, android.view.ViewParent
    public final View focusSearch(View view, int i) {
        if (view != null) {
            androidx.compose.ui.geometry.c cVarD = androidx.compose.ui.focus.a.d(view);
            androidx.compose.ui.focus.c cVarN = androidx.compose.ui.focus.a.N(i);
            if (Intrinsics.b(((androidx.compose.ui.focus.j) getFocusOwner()).d(cVarN != null ? cVarN.a : 6, cVarD, C0956n.c), Boolean.TRUE)) {
                return this;
            }
        }
        return super.focusSearch(view, i);
    }

    @NotNull
    public final C0941f0 getAndroidViewsHandler$ui_release() {
        if (this.D == null) {
            C0941f0 c0941f0 = new C0941f0(getContext());
            this.D = c0941f0;
            addView(c0941f0, -1);
            requestLayout();
        }
        C0941f0 c0941f02 = this.D;
        Intrinsics.d(c0941f02);
        return c0941f02;
    }

    public androidx.compose.ui.autofill.b getAutofill() {
        return this.y;
    }

    @NotNull
    public androidx.compose.ui.autofill.f getAutofillTree() {
        return this.q;
    }

    @NotNull
    public final Function1<Configuration, Unit> getConfigurationChangeObserver() {
        return this.x;
    }

    @NotNull
    public final androidx.compose.ui.contentcapture.c getContentCaptureManager$ui_release() {
        return this.n;
    }

    @NotNull
    public CoroutineContext getCoroutineContext() {
        return this.f;
    }

    @NotNull
    public androidx.compose.ui.unit.b getDensity() {
        return (androidx.compose.ui.unit.b) ((androidx.compose.runtime.L0) this.d).getValue();
    }

    @NotNull
    public androidx.compose.ui.draganddrop.b getDragAndDropManager() {
        return this.g;
    }

    @NotNull
    public androidx.compose.ui.focus.h getFocusOwner() {
        return this.e;
    }

    @Override // android.view.View
    public final void getFocusedRect(Rect rect) {
        Unit unit;
        androidx.compose.ui.geometry.c cVarU = u();
        if (cVarU != null) {
            rect.left = Math.round(cVarU.a);
            rect.top = Math.round(cVarU.b);
            rect.right = Math.round(cVarU.c);
            rect.bottom = Math.round(cVarU.d);
            unit = Unit.a;
        } else {
            unit = null;
        }
        if (unit == null) {
            super.getFocusedRect(rect);
        }
    }

    @NotNull
    public androidx.compose.ui.text.font.i getFontFamilyResolver() {
        return (androidx.compose.ui.text.font.i) ((androidx.compose.runtime.L0) this.q1).getValue();
    }

    @NotNull
    public InterfaceC0994h getFontLoader() {
        return this.p1;
    }

    @NotNull
    public androidx.compose.ui.graphics.E getGraphicsContext() {
        return this.p;
    }

    @NotNull
    public androidx.compose.ui.hapticfeedback.a getHapticFeedBack() {
        return this.t1;
    }

    public boolean getHasPendingMeasureOrLayout() {
        return this.H.b.q();
    }

    @NotNull
    public androidx.compose.ui.input.b getInputModeManager() {
        return this.u1;
    }

    public final long getLastMatrixRecalculationAnimationTime$ui_release() {
        return this.W;
    }

    @Override // android.view.View, android.view.ViewParent
    @NotNull
    public androidx.compose.ui.unit.k getLayoutDirection() {
        return (androidx.compose.ui.unit.k) ((androidx.compose.runtime.L0) this.s1).getValue();
    }

    public long getMeasureIteration() {
        androidx.compose.ui.node.S s = this.H;
        if (s.c) {
            return s.g;
        }
        W4.e("measureIteration should be only used during the measure/layout pass");
        throw null;
    }

    @NotNull
    public androidx.compose.ui.modifier.d getModifierLocalManager() {
        return this.v1;
    }

    @NotNull
    public androidx.compose.ui.layout.V getPlacementScope() {
        int i = androidx.compose.ui.layout.Y.b;
        return new androidx.compose.ui.layout.H(this, 1);
    }

    @NotNull
    public androidx.compose.ui.input.pointer.k getPointerIconService() {
        return this.I1;
    }

    @NotNull
    public androidx.compose.ui.node.E getRoot() {
        return this.j;
    }

    @NotNull
    public androidx.compose.ui.node.m0 getRootForTest() {
        return this.k;
    }

    public final boolean getScrollCaptureInProgress$ui_release() {
        androidx.compose.ui.scrollcapture.l lVar;
        if (Build.VERSION.SDK_INT < 31 || (lVar = this.H1) == null) {
            return false;
        }
        return ((Boolean) ((androidx.compose.runtime.L0) lVar.a).getValue()).booleanValue();
    }

    @NotNull
    public androidx.compose.ui.semantics.p getSemanticsOwner() {
        return this.l;
    }

    @NotNull
    public androidx.compose.ui.node.G getSharedDrawScope() {
        return this.c;
    }

    public boolean getShowLayoutBounds() {
        return this.C;
    }

    @NotNull
    public androidx.compose.ui.node.i0 getSnapshotObserver() {
        return this.B;
    }

    @NotNull
    public Q0 getSoftwareKeyboardController() {
        return this.o1;
    }

    @NotNull
    public androidx.compose.ui.text.input.B getTextInputService() {
        return this.m1;
    }

    @NotNull
    public S0 getTextToolbar() {
        return this.w1;
    }

    @NotNull
    public View getView() {
        return this;
    }

    @NotNull
    public Y0 getViewConfiguration() {
        return this.I;
    }

    public final C0950k getViewTreeOwners() {
        return (C0950k) this.g1.getValue();
    }

    @NotNull
    public e1 getWindowInfo() {
        return this.h;
    }

    public final androidx.compose.ui.node.f0 h(C0281h c0281h, androidx.compose.ui.input.nestedscroll.b bVar, androidx.compose.ui.graphics.layer.b bVar2) {
        Reference referencePoll;
        androidx.compose.runtime.collection.b bVar3;
        Object obj;
        if (bVar2 != null) {
            return new C0970u0(bVar2, null, this, c0281h, bVar);
        }
        do {
            androidx.work.impl.model.v vVar = this.z1;
            referencePoll = ((ReferenceQueue) vVar.c).poll();
            bVar3 = (androidx.compose.runtime.collection.b) vVar.b;
            if (referencePoll != null) {
                bVar3.n(referencePoll);
            }
        } while (referencePoll != null);
        while (true) {
            if (!bVar3.m()) {
                obj = null;
                break;
            }
            obj = ((Reference) bVar3.o(bVar3.c - 1)).get();
            if (obj != null) {
                break;
            }
        }
        androidx.compose.ui.node.f0 f0Var = (androidx.compose.ui.node.f0) obj;
        if (f0Var != null) {
            f0Var.a(c0281h, bVar);
            return f0Var;
        }
        if (isHardwareAccelerated() && Build.VERSION.SDK_INT != 28) {
            return new C0970u0(getGraphicsContext().b(), getGraphicsContext(), this, c0281h, bVar);
        }
        if (isHardwareAccelerated() && this.e1) {
            try {
                return new K0(this, c0281h, bVar);
            } catch (Throwable unused) {
                this.e1 = false;
            }
        }
        if (this.E == null) {
            if (!a1.s) {
                N.I(new View(getContext()));
            }
            C0964r0 c0964r0 = a1.t ? new C0964r0(getContext()) : new b1(getContext());
            this.E = c0964r0;
            addView(c0964r0, -1);
        }
        C0964r0 c0964r02 = this.E;
        Intrinsics.d(c0964r02);
        return new a1(this, c0964r02, c0281h, bVar);
    }

    /* JADX WARN: Removed duplicated region for block: B:38:0x00b3  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int j(android.view.MotionEvent r17) {
        /*
            Method dump skipped, instructions count: 406
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.platform.C0971v.j(android.view.MotionEvent):int");
    }

    public final void l(androidx.compose.ui.node.E e) {
        int i = 0;
        this.H.o(e, false);
        androidx.compose.runtime.collection.b bVarW = e.w();
        int i2 = bVarW.c;
        if (i2 > 0) {
            Object[] objArr = bVarW.a;
            do {
                l((androidx.compose.ui.node.E) objArr[i]);
                i++;
            } while (i < i2);
        }
    }

    public final boolean n(MotionEvent motionEvent) {
        float x = motionEvent.getX();
        float y = motionEvent.getY();
        return DefinitionKt.NO_Float_VALUE <= x && x <= ((float) getWidth()) && DefinitionKt.NO_Float_VALUE <= y && y <= ((float) getHeight());
    }

    public final boolean o(MotionEvent motionEvent) {
        MotionEvent motionEvent2;
        return (motionEvent.getPointerCount() == 1 && (motionEvent2 = this.x1) != null && motionEvent2.getPointerCount() == motionEvent.getPointerCount() && motionEvent.getRawX() == motionEvent2.getRawX() && motionEvent.getRawY() == motionEvent2.getRawY()) ? false : true;
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onAttachedToWindow() {
        androidx.lifecycle.C lifecycle;
        androidx.lifecycle.J j;
        super.onAttachedToWindow();
        ((androidx.compose.runtime.L0) this.h.a).setValue(Boolean.valueOf(hasWindowFocus()));
        l(getRoot());
        k(getRoot());
        getSnapshotObserver().a.e();
        androidx.compose.ui.autofill.a aVar = this.y;
        if (aVar != null) {
            androidx.compose.ui.autofill.e.a.a(aVar);
        }
        androidx.lifecycle.J jF = androidx.lifecycle.p0.f(this);
        androidx.savedstate.f fVarB = AbstractC3347h2.b(this);
        C0950k viewTreeOwners = getViewTreeOwners();
        if (viewTreeOwners == null || (jF != null && fVarB != null && (jF != (j = viewTreeOwners.a) || fVarB != j))) {
            if (jF == null) {
                throw new IllegalStateException("Composed into the View which doesn't propagate ViewTreeLifecycleOwner!");
            }
            if (fVarB == null) {
                throw new IllegalStateException("Composed into the View which doesn't propagateViewTreeSavedStateRegistryOwner!");
            }
            if (viewTreeOwners != null && (lifecycle = viewTreeOwners.a.getLifecycle()) != null) {
                lifecycle.b(this);
            }
            jF.getLifecycle().a(this);
            C0950k c0950k = new C0950k(jF, fVarB);
            set_viewTreeOwners(c0950k);
            Function1 function1 = this.h1;
            if (function1 != null) {
                function1.invoke(c0950k);
            }
            this.h1 = null;
        }
        ((androidx.compose.runtime.L0) this.u1.a).setValue(new androidx.compose.ui.input.a(isInTouchMode() ? 1 : 2));
        C0950k viewTreeOwners2 = getViewTreeOwners();
        androidx.lifecycle.C lifecycle2 = viewTreeOwners2 != null ? viewTreeOwners2.a.getLifecycle() : null;
        if (lifecycle2 == null) {
            W4.g("No lifecycle owner exists");
            throw null;
        }
        lifecycle2.a(this);
        lifecycle2.a(this.n);
        getViewTreeObserver().addOnGlobalLayoutListener(this.i1);
        getViewTreeObserver().addOnScrollChangedListener(this.j1);
        getViewTreeObserver().addOnTouchModeChangeListener(this.k1);
        if (Build.VERSION.SDK_INT >= 31) {
            K.a.b(this);
        }
    }

    @Override // android.view.View
    public final boolean onCheckIsTextEditor() {
        androidx.compose.ui.s sVar = (androidx.compose.ui.s) this.n1.get();
        V v = (V) (sVar != null ? sVar.b : null);
        if (v == null) {
            return this.l1.d;
        }
        androidx.compose.ui.s sVar2 = (androidx.compose.ui.s) v.d.get();
        C0974w0 c0974w0 = (C0974w0) (sVar2 != null ? sVar2.b : null);
        return c0974w0 != null && (c0974w0.e ^ true);
    }

    @Override // android.view.View
    public final void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        setDensity(K5.b(getContext()));
        int i = Build.VERSION.SDK_INT;
        if ((i >= 31 ? configuration.fontWeightAdjustment : 0) != this.r1) {
            this.r1 = i >= 31 ? configuration.fontWeightAdjustment : 0;
            setFontFamilyResolver(AbstractC3258s5.c(getContext()));
        }
        this.x.invoke(configuration);
    }

    @Override // android.view.View
    public final InputConnection onCreateInputConnection(EditorInfo editorInfo) {
        int i;
        androidx.compose.ui.s sVar = (androidx.compose.ui.s) this.n1.get();
        V v = (V) (sVar != null ? sVar.b : null);
        if (v == null) {
            androidx.compose.ui.text.input.E e = this.l1;
            if (e.d) {
                androidx.compose.ui.text.input.m mVar = e.h;
                androidx.compose.ui.text.input.A a = e.g;
                int i2 = mVar.e;
                boolean z = mVar.a;
                if (i2 == 1) {
                    i = z ? 6 : 0;
                } else if (i2 == 0) {
                    i = 1;
                } else if (i2 == 2) {
                    i = 2;
                } else if (i2 == 6) {
                    i = 5;
                } else if (i2 == 5) {
                    i = 7;
                } else if (i2 == 3) {
                    i = 3;
                } else if (i2 == 4) {
                    i = 4;
                } else {
                    if (i2 != 7) {
                        throw new IllegalStateException("invalid ImeAction");
                    }
                }
                editorInfo.imeOptions = i;
                int i3 = mVar.d;
                if (i3 == 1) {
                    editorInfo.inputType = 1;
                } else if (i3 == 2) {
                    editorInfo.inputType = 1;
                    editorInfo.imeOptions = Integer.MIN_VALUE | i;
                } else if (i3 == 3) {
                    editorInfo.inputType = 2;
                } else if (i3 == 4) {
                    editorInfo.inputType = 3;
                } else if (i3 == 5) {
                    editorInfo.inputType = 17;
                } else if (i3 == 6) {
                    editorInfo.inputType = 33;
                } else if (i3 == 7) {
                    editorInfo.inputType = 129;
                } else if (i3 == 8) {
                    editorInfo.inputType = 18;
                } else {
                    if (i3 != 9) {
                        throw new IllegalStateException("Invalid Keyboard Type");
                    }
                    editorInfo.inputType = 8194;
                }
                if (!z) {
                    int i4 = editorInfo.inputType;
                    if ((i4 & 1) == 1) {
                        editorInfo.inputType = i4 | 131072;
                        if (i2 == 1) {
                            editorInfo.imeOptions |= 1073741824;
                        }
                    }
                }
                int i5 = editorInfo.inputType;
                if ((i5 & 1) == 1) {
                    int i6 = mVar.b;
                    if (i6 == 1) {
                        editorInfo.inputType = i5 | 4096;
                    } else if (i6 == 2) {
                        editorInfo.inputType = i5 | 8192;
                    } else if (i6 == 3) {
                        editorInfo.inputType = i5 | 16384;
                    }
                    if (mVar.c) {
                        editorInfo.inputType |= 32768;
                    }
                }
                long j = a.b;
                int i7 = androidx.compose.ui.text.K.c;
                editorInfo.initialSelStart = (int) (j >> 32);
                editorInfo.initialSelEnd = (int) (j & 4294967295L);
                AbstractC3307y6.b(editorInfo, a.a.a);
                editorInfo.imeOptions |= 33554432;
                if (androidx.emoji2.text.j.c()) {
                    androidx.emoji2.text.j.a().h(editorInfo);
                }
                androidx.compose.ui.text.input.v vVar = new androidx.compose.ui.text.input.v(e.g, new com.google.firebase.platforminfo.c(e), e.h.c);
                e.i.add(new WeakReference(vVar));
                return vVar;
            }
        } else {
            androidx.compose.ui.s sVar2 = (androidx.compose.ui.s) v.d.get();
            C0974w0 c0974w0 = (C0974w0) (sVar2 != null ? sVar2.b : null);
            if (c0974w0 != null) {
                synchronized (c0974w0.c) {
                    if (c0974w0.e) {
                        return null;
                    }
                    androidx.compose.foundation.text.input.internal.D dA = c0974w0.a.a(editorInfo);
                    C0775b0 c0775b0 = new C0775b0(c0974w0, 21);
                    InputConnection qVar = Build.VERSION.SDK_INT >= 34 ? new androidx.compose.ui.text.input.q(dA, c0775b0) : new androidx.compose.ui.text.input.p(dA, c0775b0);
                    c0974w0.d.b(new WeakReference(qVar));
                    return qVar;
                }
            }
        }
        return null;
    }

    @Override // android.view.View
    public final void onCreateVirtualViewTranslationRequests(long[] jArr, int[] iArr, Consumer consumer) {
        androidx.compose.ui.contentcapture.c cVar = this.n;
        cVar.getClass();
        androidx.compose.ui.contentcapture.a.a.b(cVar, jArr, iArr, consumer);
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        androidx.compose.runtime.snapshots.v vVar = getSnapshotObserver().a;
        C0132i c0132i = vVar.h;
        if (c0132i != null) {
            c0132i.f();
        }
        vVar.b();
        C0950k viewTreeOwners = getViewTreeOwners();
        androidx.lifecycle.C lifecycle = viewTreeOwners != null ? viewTreeOwners.a.getLifecycle() : null;
        if (lifecycle == null) {
            W4.g("No lifecycle owner exists");
            throw null;
        }
        lifecycle.b(this.n);
        lifecycle.b(this);
        androidx.compose.ui.autofill.a aVar = this.y;
        if (aVar != null) {
            androidx.compose.ui.autofill.e.a.b(aVar);
        }
        getViewTreeObserver().removeOnGlobalLayoutListener(this.i1);
        getViewTreeObserver().removeOnScrollChangedListener(this.j1);
        getViewTreeObserver().removeOnTouchModeChangeListener(this.k1);
        if (Build.VERSION.SDK_INT >= 31) {
            K.a.a(this);
        }
    }

    @Override // android.view.View
    public final void onDraw(Canvas canvas) {
    }

    @Override // android.view.View
    public final void onFocusChanged(boolean z, int i, Rect rect) {
        super.onFocusChanged(z, i, rect);
        if (z || hasFocus()) {
            return;
        }
        androidx.compose.ui.focus.j jVar = (androidx.compose.ui.focus.j) getFocusOwner();
        com.bumptech.glide.manager.p pVar = jVar.h;
        boolean z2 = pVar.a;
        androidx.compose.ui.focus.t tVar = jVar.f;
        if (z2) {
            androidx.compose.ui.focus.a.e(tVar, true);
            return;
        }
        try {
            pVar.a = true;
            androidx.compose.ui.focus.a.e(tVar, true);
        } finally {
            com.bumptech.glide.manager.p.d(pVar);
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onLayout(boolean z, int i, int i2, int i3, int i4) {
        this.H.i(this.E1);
        this.F = null;
        G();
        if (this.D != null) {
            getAndroidViewsHandler$ui_release().layout(0, 0, i3 - i, i4 - i2);
        }
    }

    @Override // android.view.View
    public final void onMeasure(int i, int i2) {
        androidx.compose.ui.node.S s = this.H;
        Trace.beginSection("AndroidOwner:onMeasure");
        try {
            if (!isAttachedToWindow()) {
                l(getRoot());
            }
            long jG = g(i);
            kotlin.C c = kotlin.D.b;
            int i3 = (int) (jG >>> 32);
            int i4 = (int) (jG & 4294967295L);
            long jG2 = g(i2);
            int i5 = (int) (4294967295L & jG2);
            int iMin = Math.min((int) (jG2 >>> 32), 262142);
            int iMin2 = SubsamplingScaleImageView.TILE_SIZE_AUTO;
            int iMin3 = i5 == Integer.MAX_VALUE ? Integer.MAX_VALUE : Math.min(i5, 262142);
            int iG = L5.g(iMin3 == Integer.MAX_VALUE ? iMin : iMin3);
            if (i4 != Integer.MAX_VALUE) {
                iMin2 = Math.min(iG, i4);
            }
            long jA = L5.a(Math.min(iG, i3), iMin2, iMin, iMin3);
            androidx.compose.ui.unit.a aVar = this.F;
            if (aVar == null) {
                this.F = new androidx.compose.ui.unit.a(jA);
                this.G = false;
            } else if (!androidx.compose.ui.unit.a.b(aVar.a, jA)) {
                this.G = true;
            }
            s.p(jA);
            s.k();
            setMeasuredDimension(getRoot().x.r.a, getRoot().x.r.b);
            if (this.D != null) {
                getAndroidViewsHandler$ui_release().measure(View.MeasureSpec.makeMeasureSpec(getRoot().x.r.a, 1073741824), View.MeasureSpec.makeMeasureSpec(getRoot().x.r.b, 1073741824));
            }
            Unit unit = Unit.a;
            Trace.endSection();
        } catch (Throwable th) {
            Trace.endSection();
            throw th;
        }
    }

    @Override // android.view.View
    public final void onProvideAutofillVirtualStructure(ViewStructure viewStructure, int i) {
        androidx.compose.ui.autofill.a aVar;
        if (viewStructure == null || (aVar = this.y) == null) {
            return;
        }
        androidx.compose.ui.autofill.c cVar = androidx.compose.ui.autofill.c.a;
        androidx.compose.ui.autofill.f fVar = aVar.b;
        int iA = cVar.a(viewStructure, fVar.a.size());
        Iterator it2 = fVar.a.entrySet().iterator();
        while (it2.hasNext()) {
            Map.Entry entry = (Map.Entry) it2.next();
            int iIntValue = ((Number) entry.getKey()).intValue();
            if (entry.getValue() != null) {
                throw new ClassCastException();
            }
            Iterator it3 = it2;
            ViewStructure viewStructureB = cVar.b(viewStructure, iA);
            if (viewStructureB != null) {
                androidx.compose.ui.autofill.d dVar = androidx.compose.ui.autofill.d.a;
                AutofillId autofillIdA = dVar.a(viewStructure);
                Intrinsics.d(autofillIdA);
                dVar.g(viewStructureB, autofillIdA, iIntValue);
                cVar.d(viewStructureB, iIntValue, aVar.a.getContext().getPackageName(), null, null);
                dVar.h(viewStructureB, 1);
                throw null;
            }
            iA++;
            it2 = it3;
        }
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onResume(androidx.lifecycle.J j) {
        setShowLayoutBounds(C0972v0.b());
    }

    @Override // android.view.View
    public final void onRtlPropertiesChanged(int i) {
        if (this.b) {
            androidx.compose.ui.unit.k kVar = androidx.compose.ui.unit.k.a;
            androidx.compose.ui.unit.k kVar2 = i != 0 ? i != 1 ? null : androidx.compose.ui.unit.k.b : kVar;
            if (kVar2 != null) {
                kVar = kVar2;
            }
            setLayoutDirection(kVar);
        }
    }

    @Override // android.view.View
    public final void onScrollCaptureSearch(Rect rect, Point point, Consumer consumer) {
        androidx.compose.ui.scrollcapture.l lVar;
        if (Build.VERSION.SDK_INT < 31 || (lVar = this.H1) == null) {
            return;
        }
        lVar.a(this, getSemanticsOwner(), getCoroutineContext(), consumer);
    }

    @Override // android.view.View
    public final void onVirtualViewTranslationResponses(LongSparseArray longSparseArray) {
        androidx.compose.ui.contentcapture.c cVar = this.n;
        cVar.getClass();
        androidx.compose.ui.contentcapture.a.a.c(cVar, longSparseArray);
    }

    @Override // android.view.View
    public final void onWindowFocusChanged(boolean z) {
        boolean zB;
        ((androidx.compose.runtime.L0) this.h.a).setValue(Boolean.valueOf(z));
        this.G1 = true;
        super.onWindowFocusChanged(z);
        if (!z || getShowLayoutBounds() == (zB = C0972v0.b())) {
            return;
        }
        setShowLayoutBounds(zB);
        k(getRoot());
    }

    public final long p(long j) {
        z();
        long jB = androidx.compose.ui.graphics.J.b(j, this.M);
        return Q4.c(androidx.compose.ui.geometry.b.d(this.d1) + androidx.compose.ui.geometry.b.d(jB), androidx.compose.ui.geometry.b.e(this.d1) + androidx.compose.ui.geometry.b.e(jB));
    }

    public final void q(boolean z) {
        C0965s c0965s;
        androidx.compose.ui.node.S s = this.H;
        if (s.b.q() || ((androidx.compose.runtime.collection.b) s.e.b).m()) {
            Trace.beginSection("AndroidOwner:measureAndLayout");
            if (z) {
                try {
                    c0965s = this.E1;
                } catch (Throwable th) {
                    Trace.endSection();
                    throw th;
                }
            } else {
                c0965s = null;
            }
            if (s.i(c0965s)) {
                requestLayout();
            }
            s.a(false);
            if (this.u) {
                getViewTreeObserver().dispatchOnGlobalLayout();
                this.u = false;
            }
            Unit unit = Unit.a;
            Trace.endSection();
        }
    }

    public final void r(androidx.compose.ui.node.E e, long j) {
        androidx.compose.ui.node.S s = this.H;
        Trace.beginSection("AndroidOwner:measureAndLayout");
        try {
            s.j(e, j);
            if (!s.b.q()) {
                s.a(false);
                if (this.u) {
                    getViewTreeObserver().dispatchOnGlobalLayout();
                    this.u = false;
                }
            }
            Unit unit = Unit.a;
        } finally {
            Trace.endSection();
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public final boolean requestFocus(int i, Rect rect) {
        if (isFocused()) {
            return true;
        }
        int iOrdinal = ((androidx.compose.ui.focus.j) getFocusOwner()).f.N0().ordinal();
        if (iOrdinal == 0 || iOrdinal == 1 || iOrdinal == 2) {
            return super.requestFocus(i, rect);
        }
        if (iOrdinal != 3) {
            throw new NoWhenBranchMatchedException();
        }
        androidx.compose.ui.focus.c cVarN = androidx.compose.ui.focus.a.N(i);
        int i2 = cVarN != null ? cVarN.a : 7;
        Boolean boolD = ((androidx.compose.ui.focus.j) getFocusOwner()).d(i2, rect != null ? androidx.compose.ui.graphics.F.C(rect) : null, new androidx.compose.foundation.lazy.grid.w(i2, 5));
        if (boolD != null) {
            return boolD.booleanValue();
        }
        return false;
    }

    public final void s(androidx.compose.ui.node.f0 f0Var, boolean z) {
        ArrayList arrayList = this.r;
        if (!z) {
            if (this.t) {
                return;
            }
            arrayList.remove(f0Var);
            ArrayList arrayList2 = this.s;
            if (arrayList2 != null) {
                arrayList2.remove(f0Var);
                return;
            }
            return;
        }
        if (!this.t) {
            arrayList.add(f0Var);
            return;
        }
        ArrayList arrayList3 = this.s;
        if (arrayList3 == null) {
            arrayList3 = new ArrayList();
            this.s = arrayList3;
        }
        arrayList3.add(f0Var);
    }

    public void setAccessibilityEventBatchIntervalMillis(long j) {
        this.m.h = j;
    }

    public final void setConfigurationChangeObserver(@NotNull Function1<? super Configuration, Unit> function1) {
        this.x = function1;
    }

    public final void setContentCaptureManager$ui_release(@NotNull androidx.compose.ui.contentcapture.c cVar) {
        this.n = cVar;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r7v11 */
    /* JADX WARN: Type inference failed for: r7v12, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r7v13, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r7v14 */
    /* JADX WARN: Type inference failed for: r7v15 */
    /* JADX WARN: Type inference failed for: r7v16 */
    /* JADX WARN: Type inference failed for: r7v17 */
    /* JADX WARN: Type inference failed for: r7v18 */
    /* JADX WARN: Type inference failed for: r7v19 */
    /* JADX WARN: Type inference failed for: r7v7 */
    /* JADX WARN: Type inference failed for: r7v8, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r9v0 */
    /* JADX WARN: Type inference failed for: r9v1 */
    /* JADX WARN: Type inference failed for: r9v10 */
    /* JADX WARN: Type inference failed for: r9v11 */
    /* JADX WARN: Type inference failed for: r9v2 */
    /* JADX WARN: Type inference failed for: r9v3, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r9v4 */
    /* JADX WARN: Type inference failed for: r9v5 */
    /* JADX WARN: Type inference failed for: r9v6, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r9v8 */
    /* JADX WARN: Type inference failed for: r9v9 */
    public void setCoroutineContext(@NotNull CoroutineContext coroutineContext) {
        int i;
        int i2;
        this.f = coroutineContext;
        androidx.compose.ui.p pVar = (androidx.compose.ui.p) getRoot().w.f;
        if (pVar instanceof androidx.compose.ui.input.pointer.B) {
            ((androidx.compose.ui.input.pointer.B) pVar).O0();
        }
        androidx.compose.ui.p pVar2 = pVar.a;
        if (!pVar2.m) {
            W4.f("visitSubtree called on an unattached node");
            throw null;
        }
        androidx.compose.ui.p pVar3 = pVar2.f;
        androidx.compose.ui.node.E eV = AbstractC0910f.v(pVar);
        int[] iArrCopyOf = new int[16];
        androidx.compose.runtime.collection.b[] bVarArr = new androidx.compose.runtime.collection.b[16];
        int i3 = 0;
        while (eV != null) {
            if (pVar3 == null) {
                pVar3 = (androidx.compose.ui.p) eV.w.f;
            }
            if ((pVar3.d & 16) != 0) {
                while (pVar3 != null) {
                    if ((pVar3.c & 16) != 0) {
                        AbstractC0918n abstractC0918nF = pVar3;
                        ?? bVar = 0;
                        while (abstractC0918nF != 0) {
                            if (abstractC0918nF instanceof androidx.compose.ui.node.l0) {
                                androidx.compose.ui.node.l0 l0Var = (androidx.compose.ui.node.l0) abstractC0918nF;
                                if (l0Var instanceof androidx.compose.ui.input.pointer.B) {
                                    ((androidx.compose.ui.input.pointer.B) l0Var).O0();
                                }
                            } else if ((abstractC0918nF.c & 16) != 0 && (abstractC0918nF instanceof AbstractC0918n)) {
                                androidx.compose.ui.p pVar4 = abstractC0918nF.o;
                                int i4 = 0;
                                abstractC0918nF = abstractC0918nF;
                                bVar = bVar;
                                while (pVar4 != null) {
                                    if ((pVar4.c & 16) != 0) {
                                        i4++;
                                        bVar = bVar;
                                        if (i4 == 1) {
                                            abstractC0918nF = pVar4;
                                        } else {
                                            if (bVar == 0) {
                                                bVar = new androidx.compose.runtime.collection.b(new androidx.compose.ui.p[16]);
                                            }
                                            if (abstractC0918nF != 0) {
                                                bVar.b(abstractC0918nF);
                                                abstractC0918nF = 0;
                                            }
                                            bVar.b(pVar4);
                                        }
                                    }
                                    pVar4 = pVar4.f;
                                    abstractC0918nF = abstractC0918nF;
                                    bVar = bVar;
                                }
                                if (i4 == 1) {
                                }
                            }
                            abstractC0918nF = AbstractC0910f.f(bVar);
                        }
                    }
                    pVar3 = pVar3.f;
                }
            }
            androidx.compose.runtime.collection.b bVarW = eV.w();
            if (!bVarW.l()) {
                if (i3 >= iArrCopyOf.length) {
                    iArrCopyOf = Arrays.copyOf(iArrCopyOf, iArrCopyOf.length * 2);
                    Intrinsics.checkNotNullExpressionValue(iArrCopyOf, "copyOf(this, newSize)");
                    Object[] objArrCopyOf = Arrays.copyOf(bVarArr, bVarArr.length * 2);
                    Intrinsics.checkNotNullExpressionValue(objArrCopyOf, "copyOf(this, newSize)");
                    bVarArr = (androidx.compose.runtime.collection.b[]) objArrCopyOf;
                }
                iArrCopyOf[i3] = bVarW.c - 1;
                bVarArr[i3] = bVarW;
                i3++;
            }
            if (i3 <= 0 || (i2 = iArrCopyOf[i3 - 1]) < 0) {
                eV = null;
            } else {
                if (i3 <= 0) {
                    throw new IllegalStateException("Cannot call pop() on an empty stack. Guard with a call to isNotEmpty()");
                }
                androidx.compose.runtime.collection.b bVar2 = bVarArr[i];
                Intrinsics.d(bVar2);
                if (i2 > 0) {
                    iArrCopyOf[i] = iArrCopyOf[i] - 1;
                } else if (i2 == 0) {
                    bVarArr[i] = null;
                    i3--;
                }
                eV = (androidx.compose.ui.node.E) bVar2.a[i2];
            }
            pVar3 = null;
        }
    }

    public final void setLastMatrixRecalculationAnimationTime$ui_release(long j) {
        this.W = j;
    }

    public final void setOnViewTreeOwnersAvailable(@NotNull Function1<? super C0950k, Unit> function1) {
        C0950k viewTreeOwners = getViewTreeOwners();
        if (viewTreeOwners != null) {
            function1.invoke(viewTreeOwners);
        }
        if (isAttachedToWindow()) {
            return;
        }
        this.h1 = function1;
    }

    public void setShowLayoutBounds(boolean z) {
        this.C = z;
    }

    @Override // android.view.ViewGroup
    public final boolean shouldDelayChildPressedState() {
        return false;
    }

    public final void t() {
        if (this.z) {
            androidx.compose.runtime.snapshots.v vVar = getSnapshotObserver().a;
            synchronized (vVar.g) {
                try {
                    androidx.compose.runtime.collection.b bVar = vVar.f;
                    int i = bVar.c;
                    int i2 = 0;
                    for (int i3 = 0; i3 < i; i3++) {
                        androidx.compose.runtime.snapshots.u uVar = (androidx.compose.runtime.snapshots.u) bVar.a[i3];
                        uVar.e();
                        if (!(uVar.f.e != 0)) {
                            i2++;
                        } else if (i2 > 0) {
                            Object[] objArr = bVar.a;
                            objArr[i3 - i2] = objArr[i3];
                        }
                    }
                    Object[] objArr2 = bVar.a;
                    int i4 = i - i2;
                    Intrinsics.checkNotNullParameter(objArr2, "<this>");
                    Arrays.fill(objArr2, i4, i, (Object) null);
                    bVar.c = i4;
                    Unit unit = Unit.a;
                } catch (Throwable th) {
                    throw th;
                }
            }
            this.z = false;
        }
        C0941f0 c0941f0 = this.D;
        if (c0941f0 != null) {
            f(c0941f0);
        }
        while (this.A1.m()) {
            int i5 = this.A1.c;
            for (int i6 = 0; i6 < i5; i6++) {
                Object[] objArr3 = this.A1.a;
                Function0 function0 = (Function0) objArr3[i6];
                objArr3[i6] = null;
                if (function0 != null) {
                    function0.invoke();
                }
            }
            this.A1.p(0, i5);
        }
    }

    public final androidx.compose.ui.geometry.c u() {
        if (isFocused()) {
            androidx.compose.ui.focus.t tVarG = androidx.compose.ui.focus.a.g(((androidx.compose.ui.focus.j) getFocusOwner()).f);
            if (tVarG != null) {
                return androidx.compose.ui.focus.a.j(tVarG);
            }
            return null;
        }
        View viewFindFocus = findFocus();
        if (viewFindFocus != null) {
            return androidx.compose.ui.focus.a.d(viewFindFocus);
        }
        return null;
    }

    public final void v(androidx.compose.ui.node.E e) {
        F f = this.m;
        f.y = true;
        if (f.x()) {
            f.z(e);
        }
        androidx.compose.ui.contentcapture.c cVar = this.n;
        cVar.h = true;
        if (cVar.c() && cVar.i.add(e)) {
            cVar.j.o(Unit.a);
        }
    }

    public final void w(androidx.compose.ui.node.E e, boolean z, boolean z2, boolean z3) {
        androidx.compose.ui.node.E eS;
        androidx.compose.ui.node.E eS2;
        androidx.compose.ui.node.J j;
        androidx.compose.ui.node.F f;
        androidx.compose.ui.node.S s = this.H;
        if (!z) {
            if (s.o(e, z2) && z3) {
                B(e);
                return;
            }
            return;
        }
        s.getClass();
        if (e.c == null) {
            W4.f("Error: requestLookaheadRemeasure cannot be called on a node outside LookaheadScope");
            throw null;
        }
        androidx.compose.ui.node.L l = e.x;
        int iK = AbstractC0147y.k(l.c);
        if (iK != 0) {
            if (iK == 1) {
                return;
            }
            if (iK != 2 && iK != 3) {
                if (iK != 4) {
                    throw new NoWhenBranchMatchedException();
                }
                if (!l.g || z2) {
                    l.g = true;
                    l.d = true;
                    if (e.G) {
                        return;
                    }
                    boolean zB = Intrinsics.b(e.G(), Boolean.TRUE);
                    com.quizlet.data.repository.widget.b bVar = s.b;
                    if ((zB || (l.g && (e.q() == 1 || !((j = l.s) == null || (f = j.r) == null || !f.e())))) && ((eS = e.s()) == null || !eS.x.g)) {
                        bVar.b(e, true);
                    } else if ((e.F() || (l.d && androidx.compose.ui.node.S.h(e))) && ((eS2 = e.s()) == null || !eS2.x.d)) {
                        bVar.b(e, false);
                    }
                    if (s.d || !z3) {
                        return;
                    }
                    B(e);
                    return;
                }
                return;
            }
        }
        s.h.b(new androidx.compose.ui.node.Q(e, true, z2));
    }

    public final void x(androidx.compose.ui.node.E e, boolean z, boolean z2) {
        androidx.compose.ui.node.S s = this.H;
        if (!z) {
            s.getClass();
            int iK = AbstractC0147y.k(e.x.c);
            if (iK == 0 || iK == 1 || iK == 2 || iK == 3) {
                return;
            }
            if (iK != 4) {
                throw new NoWhenBranchMatchedException();
            }
            androidx.compose.ui.node.L l = e.x;
            if (!z2 && e.F() == l.r.t && (l.d || l.e)) {
                return;
            }
            l.e = true;
            l.f = true;
            if (!e.G && l.r.t) {
                androidx.compose.ui.node.E eS = e.s();
                if ((eS == null || !eS.x.e) && (eS == null || !eS.x.d)) {
                    s.b.b(e, false);
                }
                if (s.d) {
                    return;
                }
                B(null);
                return;
            }
            return;
        }
        s.getClass();
        int iK2 = AbstractC0147y.k(e.x.c);
        if (iK2 != 0) {
            if (iK2 == 1) {
                return;
            }
            if (iK2 != 2) {
                if (iK2 == 3) {
                    return;
                }
                if (iK2 != 4) {
                    throw new NoWhenBranchMatchedException();
                }
            }
        }
        androidx.compose.ui.node.L l2 = e.x;
        if ((l2.g || l2.h) && !z2) {
            return;
        }
        l2.h = true;
        l2.i = true;
        l2.e = true;
        l2.f = true;
        if (e.G) {
            return;
        }
        androidx.compose.ui.node.E eS2 = e.s();
        boolean zB = Intrinsics.b(e.G(), Boolean.TRUE);
        com.quizlet.data.repository.widget.b bVar = s.b;
        if (zB && ((eS2 == null || !eS2.x.g) && (eS2 == null || !eS2.x.h))) {
            bVar.b(e, true);
        } else if (e.F() && ((eS2 == null || !eS2.x.e) && (eS2 == null || !eS2.x.d))) {
            bVar.b(e, false);
        }
        if (s.d) {
            return;
        }
        B(null);
    }

    public final void y() {
        F f = this.m;
        f.y = true;
        if (f.x() && !f.J) {
            f.J = true;
            f.l.post(f.K);
        }
        androidx.compose.ui.contentcapture.c cVar = this.n;
        cVar.h = true;
        if (!cVar.c() || cVar.p) {
            return;
        }
        cVar.p = true;
        cVar.k.post(cVar.q);
    }

    public final void z() {
        if (this.c1) {
            return;
        }
        long jCurrentAnimationTimeMillis = AnimationUtils.currentAnimationTimeMillis();
        if (jCurrentAnimationTimeMillis != this.W) {
            this.W = jCurrentAnimationTimeMillis;
            InterfaceC0945h0 interfaceC0945h0 = this.F1;
            float[] fArr = this.M;
            interfaceC0945h0.e(this, fArr);
            N.x(fArr, this.V);
            ViewParent parent = getParent();
            View view = this;
            while (parent instanceof ViewGroup) {
                view = (View) parent;
                parent = ((ViewGroup) view).getParent();
            }
            int[] iArr = this.K;
            view.getLocationOnScreen(iArr);
            float f = iArr[0];
            float f2 = iArr[1];
            view.getLocationInWindow(iArr);
            this.d1 = Q4.c(f - iArr[0], f2 - iArr[1]);
        }
    }

    @Override // android.view.ViewGroup
    public final void addView(View view, int i) {
        Intrinsics.d(view);
        ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
        if (layoutParams == null) {
            layoutParams = generateDefaultLayoutParams();
        }
        addViewInLayout(view, i, layoutParams, true);
    }

    @NotNull
    public C0940f getAccessibilityManager() {
        return this.o;
    }

    @NotNull
    /* renamed from: getClipboardManager, reason: merged with bridge method [inline-methods] */
    public C0942g m4getClipboardManager() {
        return this.A;
    }

    @Override // android.view.ViewGroup
    public final void addView(View view, int i, int i2) {
        ViewGroup.LayoutParams layoutParamsGenerateDefaultLayoutParams = generateDefaultLayoutParams();
        layoutParamsGenerateDefaultLayoutParams.width = i;
        layoutParamsGenerateDefaultLayoutParams.height = i2;
        Unit unit = Unit.a;
        addViewInLayout(view, -1, layoutParamsGenerateDefaultLayoutParams, true);
    }

    @Override // android.view.ViewGroup
    public final void addView(View view, int i, ViewGroup.LayoutParams layoutParams) {
        addViewInLayout(view, i, layoutParams, true);
    }

    @Override // android.view.ViewGroup, android.view.ViewManager
    public final void addView(View view, ViewGroup.LayoutParams layoutParams) {
        addViewInLayout(view, -1, layoutParams, true);
    }
}
