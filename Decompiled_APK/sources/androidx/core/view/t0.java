package androidx.core.view;

import android.annotation.SuppressLint;
import android.graphics.Rect;
import android.os.Build;
import android.util.Log;
import android.view.View;
import android.view.WindowInsets;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3283v6;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Objects;

/* loaded from: classes.dex */
public class t0 extends z0 {
    public static boolean i = false;
    public static Method j;
    public static Class k;
    public static Field l;
    public static Field m;
    public final WindowInsets c;
    public androidx.core.graphics.e[] d;
    public androidx.core.graphics.e e;
    public D0 f;
    public androidx.core.graphics.e g;
    public int h;

    public t0(D0 d0, WindowInsets windowInsets) {
        super(d0);
        this.e = null;
        this.c = windowInsets;
    }

    @SuppressLint({"PrivateApi"})
    private static void B() throws ClassNotFoundException, SecurityException {
        try {
            j = View.class.getDeclaredMethod("getViewRootImpl", null);
            Class<?> cls = Class.forName("android.view.View$AttachInfo");
            k = cls;
            l = cls.getDeclaredField("mVisibleInsets");
            m = Class.forName("android.view.ViewRootImpl").getDeclaredField("mAttachInfo");
            l.setAccessible(true);
            m.setAccessible(true);
        } catch (ReflectiveOperationException e) {
            Log.e("WindowInsetsCompat", "Failed to get visible insets. (Reflection error). " + e.getMessage(), e);
        }
        i = true;
    }

    public static boolean C(int i2, int i3) {
        return (i2 & 6) == (i3 & 6);
    }

    @SuppressLint({"WrongConstant"})
    private androidx.core.graphics.e w(int i2, boolean z) {
        androidx.core.graphics.e eVarA = androidx.core.graphics.e.e;
        for (int i3 = 1; i3 <= 512; i3 <<= 1) {
            if ((i2 & i3) != 0) {
                eVarA = androidx.core.graphics.e.a(eVarA, x(i3, z));
            }
        }
        return eVarA;
    }

    private androidx.core.graphics.e y() {
        D0 d0 = this.f;
        return d0 != null ? d0.a.j() : androidx.core.graphics.e.e;
    }

    private androidx.core.graphics.e z(View view) throws IllegalAccessException, ClassNotFoundException, SecurityException, IllegalArgumentException, InvocationTargetException {
        if (Build.VERSION.SDK_INT >= 30) {
            throw new UnsupportedOperationException("getVisibleInsets() should not be called on API >= 30. Use WindowInsets.isVisible() instead.");
        }
        if (!i) {
            B();
        }
        Method method = j;
        if (method != null && k != null && l != null) {
            try {
                Object objInvoke = method.invoke(view, null);
                if (objInvoke == null) {
                    Log.w("WindowInsetsCompat", "Failed to get visible insets. getViewRootImpl() returned null from the provided view. This means that the view is either not attached or the method has been overridden", new NullPointerException());
                    return null;
                }
                Rect rect = (Rect) l.get(m.get(objInvoke));
                if (rect != null) {
                    return androidx.core.graphics.e.b(rect.left, rect.top, rect.right, rect.bottom);
                }
            } catch (ReflectiveOperationException e) {
                Log.e("WindowInsetsCompat", "Failed to get visible insets. (Reflection error). " + e.getMessage(), e);
            }
        }
        return null;
    }

    public boolean A(int i2) {
        if (i2 != 1 && i2 != 2) {
            if (i2 == 4) {
                return false;
            }
            if (i2 != 8 && i2 != 128) {
                return true;
            }
        }
        return !x(i2, false).equals(androidx.core.graphics.e.e);
    }

    @Override // androidx.core.view.z0
    public void d(View view) throws IllegalAccessException, ClassNotFoundException, SecurityException, IllegalArgumentException, InvocationTargetException {
        androidx.core.graphics.e eVarZ = z(view);
        if (eVarZ == null) {
            eVarZ = androidx.core.graphics.e.e;
        }
        s(eVarZ);
    }

    @Override // androidx.core.view.z0
    public void e(D0 d0) {
        d0.a.t(this.f);
        androidx.core.graphics.e eVar = this.g;
        z0 z0Var = d0.a;
        z0Var.s(eVar);
        z0Var.v(this.h);
    }

    @Override // androidx.core.view.z0
    public boolean equals(Object obj) {
        if (!super.equals(obj)) {
            return false;
        }
        t0 t0Var = (t0) obj;
        return Objects.equals(this.g, t0Var.g) && C(this.h, t0Var.h);
    }

    @Override // androidx.core.view.z0
    public androidx.core.graphics.e g(int i2) {
        return w(i2, false);
    }

    @Override // androidx.core.view.z0
    public androidx.core.graphics.e h(int i2) {
        return w(i2, true);
    }

    @Override // androidx.core.view.z0
    public final androidx.core.graphics.e l() {
        if (this.e == null) {
            WindowInsets windowInsets = this.c;
            this.e = androidx.core.graphics.e.b(windowInsets.getSystemWindowInsetLeft(), windowInsets.getSystemWindowInsetTop(), windowInsets.getSystemWindowInsetRight(), windowInsets.getSystemWindowInsetBottom());
        }
        return this.e;
    }

    @Override // androidx.core.view.z0
    public D0 n(int i2, int i3, int i4, int i5) {
        D0 d0H = D0.h(null, this.c);
        int i6 = Build.VERSION.SDK_INT;
        s0 r0Var = i6 >= 34 ? new r0(d0H) : i6 >= 30 ? new q0(d0H) : i6 >= 29 ? new p0(d0H) : new n0(d0H);
        r0Var.g(D0.e(l(), i2, i3, i4, i5));
        r0Var.e(D0.e(j(), i2, i3, i4, i5));
        return r0Var.b();
    }

    @Override // androidx.core.view.z0
    public boolean p() {
        return this.c.isRound();
    }

    @Override // androidx.core.view.z0
    @SuppressLint({"WrongConstant"})
    public boolean q(int i2) {
        for (int i3 = 1; i3 <= 512; i3 <<= 1) {
            if ((i2 & i3) != 0 && !A(i3)) {
                return false;
            }
        }
        return true;
    }

    @Override // androidx.core.view.z0
    public void r(androidx.core.graphics.e[] eVarArr) {
        this.d = eVarArr;
    }

    @Override // androidx.core.view.z0
    public void s(androidx.core.graphics.e eVar) {
        this.g = eVar;
    }

    @Override // androidx.core.view.z0
    public void t(D0 d0) {
        this.f = d0;
    }

    @Override // androidx.core.view.z0
    public void v(int i2) {
        this.h = i2;
    }

    public androidx.core.graphics.e x(int i2, boolean z) {
        androidx.core.graphics.e eVarJ;
        int i3;
        androidx.core.graphics.e eVar = androidx.core.graphics.e.e;
        if (i2 != 1) {
            if (i2 != 2) {
                if (i2 == 8) {
                    androidx.core.graphics.e[] eVarArr = this.d;
                    eVarJ = eVarArr != null ? eVarArr[AbstractC3283v6.a(8)] : null;
                    if (eVarJ != null) {
                        return eVarJ;
                    }
                    androidx.core.graphics.e eVarL = l();
                    androidx.core.graphics.e eVarY = y();
                    int i4 = eVarL.d;
                    if (i4 > eVarY.d) {
                        return androidx.core.graphics.e.b(0, 0, 0, i4);
                    }
                    androidx.core.graphics.e eVar2 = this.g;
                    if (eVar2 != null && !eVar2.equals(eVar) && (i3 = this.g.d) > eVarY.d) {
                        return androidx.core.graphics.e.b(0, 0, 0, i3);
                    }
                } else {
                    if (i2 == 16) {
                        return k();
                    }
                    if (i2 == 32) {
                        return i();
                    }
                    if (i2 == 64) {
                        return m();
                    }
                    if (i2 == 128) {
                        D0 d0 = this.f;
                        C1054k c1054kF = d0 != null ? d0.a.f() : f();
                        if (c1054kF != null) {
                            int i5 = Build.VERSION.SDK_INT;
                            return androidx.core.graphics.e.b(i5 >= 28 ? androidx.arch.core.executor.d.j(c1054kF.a) : 0, i5 >= 28 ? androidx.arch.core.executor.d.l(c1054kF.a) : 0, i5 >= 28 ? androidx.arch.core.executor.d.k(c1054kF.a) : 0, i5 >= 28 ? androidx.arch.core.executor.d.i(c1054kF.a) : 0);
                        }
                    }
                }
            } else {
                if (z) {
                    androidx.core.graphics.e eVarY2 = y();
                    androidx.core.graphics.e eVarJ2 = j();
                    return androidx.core.graphics.e.b(Math.max(eVarY2.a, eVarJ2.a), 0, Math.max(eVarY2.c, eVarJ2.c), Math.max(eVarY2.d, eVarJ2.d));
                }
                if ((this.h & 2) == 0) {
                    androidx.core.graphics.e eVarL2 = l();
                    D0 d02 = this.f;
                    eVarJ = d02 != null ? d02.a.j() : null;
                    int iMin = eVarL2.d;
                    if (eVarJ != null) {
                        iMin = Math.min(iMin, eVarJ.d);
                    }
                    return androidx.core.graphics.e.b(eVarL2.a, 0, eVarL2.c, iMin);
                }
            }
        } else {
            if (z) {
                return androidx.core.graphics.e.b(0, Math.max(y().b, l().b), 0, 0);
            }
            if ((this.h & 4) == 0) {
                return androidx.core.graphics.e.b(0, l().b, 0, 0);
            }
        }
        return eVar;
    }

    public t0(D0 d0, t0 t0Var) {
        this(d0, new WindowInsets(t0Var.c));
    }
}
