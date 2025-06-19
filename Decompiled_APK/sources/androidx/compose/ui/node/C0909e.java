package androidx.compose.ui.node;

import androidx.compose.ui.platform.C0971v;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.ui.node.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0909e extends kotlin.jvm.internal.r implements Function1 {
    public static final C0909e b = new C0909e(1, 0);
    public static final C0909e c = new C0909e(1, 1);
    public static final C0909e d = new C0909e(1, 2);
    public static final C0909e e = new C0909e(1, 3);
    public static final C0909e f = new C0909e(1, 4);
    public static final C0909e g = new C0909e(1, 5);
    public static final C0909e h = new C0909e(1, 6);
    public static final C0909e i = new C0909e(1, 7);
    public static final C0909e j = new C0909e(1, 8);
    public static final C0909e k = new C0909e(1, 9);
    public static final C0909e l = new C0909e(1, 10);
    public static final C0909e m = new C0909e(1, 11);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0909e(int i2, int i3) {
        super(i2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                ((C0907c) obj).O0();
                break;
            case 1:
                k0 k0Var = (k0) obj;
                if (k0Var.u()) {
                    k0Var.b.A0(k0Var);
                }
                break;
            case 2:
                f0 f0Var = ((a0) obj).D;
                if (f0Var != null) {
                    f0Var.invalidate();
                }
                break;
            case 3:
                a0 a0Var = (a0) obj;
                if (a0Var.u()) {
                    C0924u c0924u = a0Var.z;
                    if (c0924u == null) {
                        a0Var.s1(true);
                    } else {
                        C0924u c0924u2 = a0.G;
                        c0924u2.getClass();
                        c0924u2.a = c0924u.a;
                        c0924u2.b = c0924u.b;
                        c0924u2.c = c0924u.c;
                        c0924u2.d = c0924u.d;
                        c0924u2.e = c0924u.e;
                        c0924u2.f = c0924u.f;
                        c0924u2.g = c0924u.g;
                        c0924u2.h = c0924u.h;
                        c0924u2.i = c0924u.i;
                        a0Var.s1(true);
                        if (c0924u2.a != c0924u.a || c0924u2.b != c0924u.b || c0924u2.c != c0924u.c || c0924u2.d != c0924u.d || c0924u2.e != c0924u.e || c0924u2.f != c0924u.f || c0924u2.g != c0924u.g || c0924u2.h != c0924u.h || !androidx.compose.ui.graphics.Z.a(c0924u2.i, c0924u.i)) {
                            E e2 = a0Var.l;
                            L l2 = e2.x;
                            if (l2.n > 0) {
                                if (l2.m || l2.l) {
                                    e2.S(false);
                                }
                                l2.r.C0();
                            }
                            C0971v c0971v = e2.i;
                            if (c0971v != null) {
                                ((androidx.compose.runtime.collection.b) c0971v.H.e.b).b(e2);
                                e2.F = true;
                                c0971v.B(null);
                            }
                        }
                    }
                }
                break;
            case 4:
                d0 d0Var = (d0) obj;
                if (d0Var.u()) {
                    d0Var.a.k0();
                }
                break;
            case 5:
                E e3 = (E) obj;
                if (e3.E()) {
                    e3.S(false);
                }
                break;
            case 6:
                E e4 = (E) obj;
                if (e4.E()) {
                    e4.S(false);
                }
                break;
            case 7:
                E e5 = (E) obj;
                if (e5.E()) {
                    e5.Q(false);
                }
                break;
            case 8:
                E e6 = (E) obj;
                if (e6.E()) {
                    e6.Q(false);
                }
                break;
            case 9:
                E e7 = (E) obj;
                if (e7.E()) {
                    E.R(e7, false, 7);
                }
                break;
            case 10:
                E e8 = (E) obj;
                if (e8.E()) {
                    E.T(e8, false, 7);
                }
                break;
            default:
                E e9 = (E) obj;
                if (e9.E()) {
                    e9.C();
                }
                break;
        }
        return Unit.a;
    }
}
