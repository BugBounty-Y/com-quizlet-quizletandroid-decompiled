package androidx.compose.ui.platform;

import android.graphics.Canvas;
import android.graphics.Rect;
import android.os.Build;
import android.view.View;
import androidx.compose.animation.C0281h;
import androidx.compose.material3.C0634i2;
import androidx.compose.ui.graphics.C0844d;
import androidx.compose.ui.graphics.C0859t;
import androidx.compose.ui.graphics.InterfaceC0858s;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class a1 extends View implements androidx.compose.ui.node.f0 {
    public static final C0634i2 p = new C0634i2(2);
    public static Method q;
    public static Field r;
    public static boolean s;
    public static boolean t;
    public final C0971v a;
    public final C0964r0 b;
    public C0281h c;
    public androidx.compose.ui.input.nestedscroll.b d;
    public final C0 e;
    public boolean f;
    public Rect g;
    public boolean h;
    public boolean i;
    public final C0859t j;
    public final C0978y0 k;
    public long l;
    public boolean m;
    public final long n;
    public int o;

    public a1(C0971v c0971v, C0964r0 c0964r0, C0281h c0281h, androidx.compose.ui.input.nestedscroll.b bVar) {
        super(c0971v.getContext());
        this.a = c0971v;
        this.b = c0964r0;
        this.c = c0281h;
        this.d = bVar;
        this.e = new C0();
        this.j = new C0859t();
        this.k = new C0978y0(C0951k0.d);
        this.l = androidx.compose.ui.graphics.Z.b;
        this.m = true;
        setWillNotDraw(false);
        c0964r0.addView(this);
        this.n = View.generateViewId();
    }

    private final androidx.compose.ui.graphics.O getManualClipPath() {
        if (!getClipToOutline()) {
            return null;
        }
        C0 c0 = this.e;
        if (!c0.g) {
            return null;
        }
        c0.d();
        return c0.e;
    }

    private final void setInvalidated(boolean z) {
        if (z != this.h) {
            this.h = z;
            this.a.s(this, z);
        }
    }

    @Override // androidx.compose.ui.node.f0
    public final void a(C0281h c0281h, androidx.compose.ui.input.nestedscroll.b bVar) {
        this.b.addView(this);
        this.f = false;
        this.i = false;
        this.l = androidx.compose.ui.graphics.Z.b;
        this.c = c0281h;
        this.d = bVar;
    }

    @Override // androidx.compose.ui.node.f0
    public final void b(float[] fArr) {
        androidx.compose.ui.graphics.J.g(fArr, this.k.b(this));
    }

    @Override // androidx.compose.ui.node.f0
    public final boolean c(long j) {
        androidx.compose.ui.graphics.N n;
        float fD = androidx.compose.ui.geometry.b.d(j);
        float fE = androidx.compose.ui.geometry.b.e(j);
        if (this.f) {
            if (DefinitionKt.NO_Float_VALUE > fD || fD >= getWidth() || DefinitionKt.NO_Float_VALUE > fE || fE >= getHeight()) {
                return false;
            }
        } else if (getClipToOutline()) {
            C0 c0 = this.e;
            if (c0.m && (n = c0.c) != null) {
                return N.z(n, androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.b.e(j));
            }
            return true;
        }
        return true;
    }

    @Override // androidx.compose.ui.node.f0
    public final void d(androidx.compose.ui.graphics.S s2) {
        androidx.compose.ui.input.nestedscroll.b bVar;
        int i = s2.a | this.o;
        if ((i & 4096) != 0) {
            long j = s2.n;
            this.l = j;
            setPivotX(androidx.compose.ui.graphics.Z.b(j) * getWidth());
            setPivotY(androidx.compose.ui.graphics.Z.c(this.l) * getHeight());
        }
        if ((i & 1) != 0) {
            setScaleX(s2.b);
        }
        if ((i & 2) != 0) {
            setScaleY(s2.c);
        }
        if ((i & 4) != 0) {
            setAlpha(s2.d);
        }
        if ((i & 8) != 0) {
            setTranslationX(s2.e);
        }
        if ((i & 16) != 0) {
            setTranslationY(s2.f);
        }
        if ((i & 32) != 0) {
            setElevation(s2.g);
        }
        if ((i & 1024) != 0) {
            setRotation(s2.l);
        }
        if ((i & 256) != 0) {
            setRotationX(s2.j);
        }
        if ((i & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0) {
            setRotationY(s2.k);
        }
        if ((i & 2048) != 0) {
            setCameraDistancePx(s2.m);
        }
        boolean z = true;
        boolean z2 = getManualClipPath() != null;
        boolean z3 = s2.p;
        com.quizlet.shared.usecase.folderstudymaterials.d dVar = androidx.compose.ui.graphics.F.a;
        boolean z4 = z3 && s2.o != dVar;
        if ((i & 24576) != 0) {
            this.f = z3 && s2.o == dVar;
            l();
            setClipToOutline(z4);
        }
        boolean zC = this.e.c(s2.v, s2.d, z4, s2.g, s2.r);
        C0 c0 = this.e;
        if (c0.f) {
            setOutlineProvider(c0.b() != null ? p : null);
        }
        boolean z5 = getManualClipPath() != null;
        if (z2 != z5 || (z5 && zC)) {
            invalidate();
        }
        if (!this.i && getElevation() > DefinitionKt.NO_Float_VALUE && (bVar = this.d) != null) {
            bVar.invoke();
        }
        if ((i & 7963) != 0) {
            this.k.c();
        }
        int i2 = Build.VERSION.SDK_INT;
        if (i2 >= 28) {
            int i3 = i & 64;
            c1 c1Var = c1.a;
            if (i3 != 0) {
                c1Var.a(this, androidx.compose.ui.graphics.F.A(s2.h));
            }
            if ((i & 128) != 0) {
                c1Var.b(this, androidx.compose.ui.graphics.F.A(s2.i));
            }
        }
        if (i2 >= 31 && (131072 & i) != 0) {
            d1.a.a(this, s2.u);
        }
        if ((i & 32768) != 0) {
            int i4 = s2.q;
            if (i4 == 1) {
                setLayerType(2, null);
            } else if (i4 == 2) {
                setLayerType(0, null);
                z = false;
            } else {
                setLayerType(0, null);
            }
            this.m = z;
        }
        this.o = s2.a;
    }

    @Override // androidx.compose.ui.node.f0
    public final void destroy() {
        setInvalidated(false);
        C0971v c0971v = this.a;
        c0971v.z = true;
        this.c = null;
        this.d = null;
        c0971v.A(this);
        this.b.removeViewInLayout(this);
    }

    @Override // android.view.View
    public final void dispatchDraw(Canvas canvas) {
        boolean z;
        C0859t c0859t = this.j;
        C0844d c0844d = c0859t.a;
        Canvas canvas2 = c0844d.a;
        c0844d.a = canvas;
        if (getManualClipPath() == null && canvas.isHardwareAccelerated()) {
            z = false;
        } else {
            c0844d.e();
            this.e.a(c0844d);
            z = true;
        }
        C0281h c0281h = this.c;
        if (c0281h != null) {
            c0281h.invoke(c0844d, null);
        }
        if (z) {
            c0844d.q();
        }
        c0859t.a.a = canvas2;
        setInvalidated(false);
    }

    @Override // androidx.compose.ui.node.f0
    public final long e(long j, boolean z) {
        C0978y0 c0978y0 = this.k;
        if (!z) {
            return androidx.compose.ui.graphics.J.b(j, c0978y0.b(this));
        }
        float[] fArrA = c0978y0.a(this);
        if (fArrA != null) {
            return androidx.compose.ui.graphics.J.b(j, fArrA);
        }
        return 9187343241974906880L;
    }

    @Override // androidx.compose.ui.node.f0
    public final void f(long j) {
        int i = (int) (j >> 32);
        int i2 = (int) (j & 4294967295L);
        if (i == getWidth() && i2 == getHeight()) {
            return;
        }
        setPivotX(androidx.compose.ui.graphics.Z.b(this.l) * i);
        setPivotY(androidx.compose.ui.graphics.Z.c(this.l) * i2);
        setOutlineProvider(this.e.b() != null ? p : null);
        layout(getLeft(), getTop(), getLeft() + i, getTop() + i2);
        l();
        this.k.c();
    }

    @Override // android.view.View
    public final void forceLayout() {
    }

    @Override // androidx.compose.ui.node.f0
    public final void g(InterfaceC0858s interfaceC0858s, androidx.compose.ui.graphics.layer.b bVar) {
        boolean z = getElevation() > DefinitionKt.NO_Float_VALUE;
        this.i = z;
        if (z) {
            interfaceC0858s.t();
        }
        this.b.a(interfaceC0858s, this, getDrawingTime());
        if (this.i) {
            interfaceC0858s.f();
        }
    }

    public final float getCameraDistancePx() {
        return getCameraDistance() / getResources().getDisplayMetrics().densityDpi;
    }

    @NotNull
    public final C0964r0 getContainer() {
        return this.b;
    }

    public long getLayerId() {
        return this.n;
    }

    @NotNull
    public final C0971v getOwnerView() {
        return this.a;
    }

    public long getOwnerViewId() {
        if (Build.VERSION.SDK_INT >= 29) {
            return Z0.a(this.a);
        }
        return -1L;
    }

    @Override // androidx.compose.ui.node.f0
    public final void h(float[] fArr) {
        float[] fArrA = this.k.a(this);
        if (fArrA != null) {
            androidx.compose.ui.graphics.J.g(fArr, fArrA);
        }
    }

    @Override // android.view.View
    public final boolean hasOverlappingRendering() {
        return this.m;
    }

    @Override // androidx.compose.ui.node.f0
    public final void i(androidx.camera.camera2.internal.q0 q0Var, boolean z) {
        C0978y0 c0978y0 = this.k;
        if (!z) {
            androidx.compose.ui.graphics.J.c(c0978y0.b(this), q0Var);
            return;
        }
        float[] fArrA = c0978y0.a(this);
        if (fArrA != null) {
            androidx.compose.ui.graphics.J.c(fArrA, q0Var);
            return;
        }
        q0Var.b = DefinitionKt.NO_Float_VALUE;
        q0Var.c = DefinitionKt.NO_Float_VALUE;
        q0Var.d = DefinitionKt.NO_Float_VALUE;
        q0Var.e = DefinitionKt.NO_Float_VALUE;
    }

    @Override // android.view.View, androidx.compose.ui.node.f0
    public final void invalidate() {
        if (this.h) {
            return;
        }
        setInvalidated(true);
        super.invalidate();
        this.a.invalidate();
    }

    @Override // androidx.compose.ui.node.f0
    public final void j(long j) {
        int i = (int) (j >> 32);
        int left = getLeft();
        C0978y0 c0978y0 = this.k;
        if (i != left) {
            offsetLeftAndRight(i - getLeft());
            c0978y0.c();
        }
        int i2 = (int) (j & 4294967295L);
        if (i2 != getTop()) {
            offsetTopAndBottom(i2 - getTop());
            c0978y0.c();
        }
    }

    @Override // androidx.compose.ui.node.f0
    public final void k() {
        if (!this.h || t) {
            return;
        }
        N.I(this);
        setInvalidated(false);
    }

    public final void l() {
        Rect rect;
        if (this.f) {
            Rect rect2 = this.g;
            if (rect2 == null) {
                this.g = new Rect(0, 0, getWidth(), getHeight());
            } else {
                Intrinsics.d(rect2);
                rect2.set(0, 0, getWidth(), getHeight());
            }
            rect = this.g;
        } else {
            rect = null;
        }
        setClipBounds(rect);
    }

    @Override // android.view.View
    public final void onLayout(boolean z, int i, int i2, int i3, int i4) {
    }

    public final void setCameraDistancePx(float f) {
        setCameraDistance(f * getResources().getDisplayMetrics().densityDpi);
    }
}
