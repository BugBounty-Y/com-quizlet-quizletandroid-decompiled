package androidx.compose.foundation;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.foundation.text.C0491h;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0833w;
import androidx.compose.runtime.InterfaceC0819s;
import androidx.compose.ui.text.C0995g;
import androidx.compose.ui.text.input.C0998a;
import com.appsflyer.attribution.RequestError;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.F4;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class P0 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public P0(int i, androidx.compose.foundation.text.y0 y0Var, kotlin.jvm.internal.F f) {
        super(1);
        this.a = 1;
        this.b = i;
        this.c = y0Var;
        this.d = f;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        Integer numD;
        Integer numC;
        Integer numC2;
        Integer numD2;
        androidx.compose.ui.text.H h;
        androidx.compose.ui.text.H h2;
        androidx.compose.foundation.text.K0 k0;
        androidx.compose.foundation.text.K0 k02;
        androidx.compose.ui.text.H h3;
        androidx.compose.ui.text.H h4;
        androidx.compose.foundation.text.K0 k03;
        androidx.compose.foundation.text.K0 k04;
        Integer numC3;
        Integer numD3;
        Integer numD4;
        Integer numC4;
        androidx.work.impl.model.v vVar;
        int i;
        boolean z;
        Object obj2 = this.d;
        int i2 = this.b;
        Object obj3 = this.c;
        switch (this.a) {
            case 0:
                androidx.compose.ui.layout.V v = (androidx.compose.ui.layout.V) obj;
                Q0 q0 = (Q0) obj3;
                int i3 = -kotlin.ranges.l.c(q0.n.g(), 0, i2);
                boolean z2 = q0.o;
                int i4 = z2 ? 0 : i3;
                if (!z2) {
                    i3 = 0;
                }
                O0 o0 = new O0((androidx.compose.ui.layout.W) obj2, i4, i3, 0);
                v.a = true;
                o0.invoke(v);
                v.a = false;
                break;
            case 1:
                androidx.compose.foundation.text.selection.g0 g0Var = (androidx.compose.foundation.text.selection.g0) obj;
                androidx.compose.ui.text.input.A a = null;
                androidx.compose.foundation.text.y0 y0Var = (androidx.compose.foundation.text.y0) obj3;
                switch (AbstractC0147y.k(i2)) {
                    case 0:
                        g0Var.e.a = null;
                        if (g0Var.g.a.length() > 0) {
                            if (!androidx.compose.ui.text.K.b(g0Var.f)) {
                                if (!g0Var.e()) {
                                    int iD = androidx.compose.ui.text.K.d(g0Var.f);
                                    g0Var.o(iD, iD);
                                    break;
                                } else {
                                    int iE = androidx.compose.ui.text.K.e(g0Var.f);
                                    g0Var.o(iE, iE);
                                    break;
                                }
                            } else {
                                g0Var.h();
                                Unit unit = Unit.a;
                                break;
                            }
                        }
                        break;
                    case 1:
                        g0Var.e.a = null;
                        if (g0Var.g.a.length() > 0) {
                            if (!androidx.compose.ui.text.K.b(g0Var.f)) {
                                if (!g0Var.e()) {
                                    int iE2 = androidx.compose.ui.text.K.e(g0Var.f);
                                    g0Var.o(iE2, iE2);
                                    break;
                                } else {
                                    int iD2 = androidx.compose.ui.text.K.d(g0Var.f);
                                    g0Var.o(iD2, iD2);
                                    break;
                                }
                            } else {
                                g0Var.k();
                                Unit unit2 = Unit.a;
                                break;
                            }
                        }
                        break;
                    case 2:
                        androidx.compose.foundation.text.selection.o0 o0Var = g0Var.e;
                        o0Var.a = null;
                        if (g0Var.g.a.length() > 0) {
                            if (!g0Var.e()) {
                                o0Var.a = null;
                                if (g0Var.g.a.length() > 0 && (numD = g0Var.d()) != null) {
                                    int iIntValue = numD.intValue();
                                    g0Var.o(iIntValue, iIntValue);
                                    break;
                                }
                            } else {
                                o0Var.a = null;
                                if (g0Var.g.a.length() > 0 && (numC = g0Var.c()) != null) {
                                    int iIntValue2 = numC.intValue();
                                    g0Var.o(iIntValue2, iIntValue2);
                                    break;
                                }
                            }
                        }
                        break;
                    case 3:
                        androidx.compose.foundation.text.selection.o0 o0Var2 = g0Var.e;
                        o0Var2.a = null;
                        if (g0Var.g.a.length() > 0) {
                            if (!g0Var.e()) {
                                o0Var2.a = null;
                                if (g0Var.g.a.length() > 0 && (numC2 = g0Var.c()) != null) {
                                    int iIntValue3 = numC2.intValue();
                                    g0Var.o(iIntValue3, iIntValue3);
                                    break;
                                }
                            } else {
                                o0Var2.a = null;
                                if (g0Var.g.a.length() > 0 && (numD2 = g0Var.d()) != null) {
                                    int iIntValue4 = numD2.intValue();
                                    g0Var.o(iIntValue4, iIntValue4);
                                    break;
                                }
                            }
                        }
                        break;
                    case 4:
                        g0Var.i();
                        break;
                    case 5:
                        g0Var.j();
                        break;
                    case 6:
                        g0Var.m();
                        break;
                    case 7:
                        g0Var.l();
                        break;
                    case 8:
                        g0Var.e.a = null;
                        if (g0Var.g.a.length() > 0) {
                            if (!g0Var.e()) {
                                g0Var.l();
                                break;
                            } else {
                                g0Var.m();
                                break;
                            }
                        }
                        break;
                    case 9:
                        g0Var.e.a = null;
                        if (g0Var.g.a.length() > 0) {
                            if (!g0Var.e()) {
                                g0Var.m();
                                break;
                            } else {
                                g0Var.l();
                                break;
                            }
                        }
                        break;
                    case 10:
                        if (g0Var.g.a.length() > 0 && (h = g0Var.c) != null) {
                            int iF = g0Var.f(h, -1);
                            g0Var.o(iF, iF);
                            break;
                        }
                        break;
                    case 11:
                        if (g0Var.g.a.length() > 0 && (h2 = g0Var.c) != null) {
                            int iF2 = g0Var.f(h2, 1);
                            g0Var.o(iF2, iF2);
                            break;
                        }
                        break;
                    case 12:
                        if (g0Var.g.a.length() > 0 && (k0 = g0Var.i) != null) {
                            int iG = g0Var.g(k0, -1);
                            g0Var.o(iG, iG);
                            break;
                        }
                        break;
                    case 13:
                        if (g0Var.g.a.length() > 0 && (k02 = g0Var.i) != null) {
                            int iG2 = g0Var.g(k02, 1);
                            g0Var.o(iG2, iG2);
                            break;
                        }
                        break;
                    case 14:
                        g0Var.e.a = null;
                        if (g0Var.g.a.length() > 0) {
                            g0Var.o(0, 0);
                            break;
                        }
                        break;
                    case 15:
                        g0Var.e.a = null;
                        C0995g c0995g = g0Var.g;
                        if (c0995g.a.length() > 0) {
                            int length = c0995g.a.length();
                            g0Var.o(length, length);
                            break;
                        }
                        break;
                    case 16:
                        y0Var.b.d(false);
                        break;
                    case 17:
                        y0Var.b.n();
                        break;
                    case 18:
                        y0Var.b.f();
                        break;
                    case 19:
                        List listA = g0Var.a(C0491h.i);
                        if (listA != null) {
                            y0Var.a(listA);
                            break;
                        }
                        break;
                    case 20:
                        List listA2 = g0Var.a(C0491h.j);
                        if (listA2 != null) {
                            y0Var.a(listA2);
                            break;
                        }
                        break;
                    case 21:
                        List listA3 = g0Var.a(C0491h.k);
                        if (listA3 != null) {
                            y0Var.a(listA3);
                            break;
                        }
                        break;
                    case EventType.WINDOW_STATE /* 22 */:
                        List listA4 = g0Var.a(C0491h.l);
                        if (listA4 != null) {
                            y0Var.a(listA4);
                            break;
                        }
                        break;
                    case EventType.AUDIO /* 23 */:
                        List listA5 = g0Var.a(C0491h.m);
                        if (listA5 != null) {
                            y0Var.a(listA5);
                            break;
                        }
                        break;
                    case EventType.VIDEO /* 24 */:
                        List listA6 = g0Var.a(C0491h.n);
                        if (listA6 != null) {
                            y0Var.a(listA6);
                            break;
                        }
                        break;
                    case EventType.SUBS /* 25 */:
                        g0Var.e.a = null;
                        C0995g c0995g2 = g0Var.g;
                        if (c0995g2.a.length() > 0) {
                            g0Var.o(0, c0995g2.a.length());
                            break;
                        }
                        break;
                    case EventType.CDN /* 26 */:
                        g0Var.h();
                        g0Var.n();
                        break;
                    case 27:
                        g0Var.k();
                        g0Var.n();
                        break;
                    case 28:
                        if (g0Var.g.a.length() > 0 && (h3 = g0Var.c) != null) {
                            int iF3 = g0Var.f(h3, -1);
                            g0Var.o(iF3, iF3);
                        }
                        g0Var.n();
                        break;
                    case 29:
                        if (g0Var.g.a.length() > 0 && (h4 = g0Var.c) != null) {
                            int iF4 = g0Var.f(h4, 1);
                            g0Var.o(iF4, iF4);
                        }
                        g0Var.n();
                        break;
                    case 30:
                        if (g0Var.g.a.length() > 0 && (k03 = g0Var.i) != null) {
                            int iG3 = g0Var.g(k03, -1);
                            g0Var.o(iG3, iG3);
                        }
                        g0Var.n();
                        break;
                    case 31:
                        if (g0Var.g.a.length() > 0 && (k04 = g0Var.i) != null) {
                            int iG4 = g0Var.g(k04, 1);
                            g0Var.o(iG4, iG4);
                        }
                        g0Var.n();
                        break;
                    case 32:
                        g0Var.e.a = null;
                        if (g0Var.g.a.length() > 0) {
                            g0Var.o(0, 0);
                        }
                        g0Var.n();
                        break;
                    case 33:
                        g0Var.e.a = null;
                        C0995g c0995g3 = g0Var.g;
                        if (c0995g3.a.length() > 0) {
                            int length2 = c0995g3.a.length();
                            g0Var.o(length2, length2);
                        }
                        g0Var.n();
                        break;
                    case 34:
                        androidx.compose.foundation.text.selection.o0 o0Var3 = g0Var.e;
                        o0Var3.a = null;
                        if (g0Var.g.a.length() > 0) {
                            if (g0Var.e()) {
                                o0Var3.a = null;
                                if (g0Var.g.a.length() > 0 && (numD3 = g0Var.d()) != null) {
                                    int iIntValue5 = numD3.intValue();
                                    g0Var.o(iIntValue5, iIntValue5);
                                }
                            } else {
                                o0Var3.a = null;
                                if (g0Var.g.a.length() > 0 && (numC3 = g0Var.c()) != null) {
                                    int iIntValue6 = numC3.intValue();
                                    g0Var.o(iIntValue6, iIntValue6);
                                }
                            }
                        }
                        g0Var.n();
                        break;
                    case 35:
                        androidx.compose.foundation.text.selection.o0 o0Var4 = g0Var.e;
                        o0Var4.a = null;
                        if (g0Var.g.a.length() > 0) {
                            if (g0Var.e()) {
                                o0Var4.a = null;
                                if (g0Var.g.a.length() > 0 && (numC4 = g0Var.c()) != null) {
                                    int iIntValue7 = numC4.intValue();
                                    g0Var.o(iIntValue7, iIntValue7);
                                }
                            } else {
                                o0Var4.a = null;
                                if (g0Var.g.a.length() > 0 && (numD4 = g0Var.d()) != null) {
                                    int iIntValue8 = numD4.intValue();
                                    g0Var.o(iIntValue8, iIntValue8);
                                }
                            }
                        }
                        g0Var.n();
                        break;
                    case 36:
                        g0Var.i();
                        g0Var.n();
                        break;
                    case 37:
                        g0Var.j();
                        g0Var.n();
                        break;
                    case 38:
                        g0Var.m();
                        g0Var.n();
                        break;
                    case 39:
                        g0Var.l();
                        g0Var.n();
                        break;
                    case RequestError.NETWORK_FAILURE /* 40 */:
                        g0Var.e.a = null;
                        if (g0Var.g.a.length() > 0) {
                            if (g0Var.e()) {
                                g0Var.m();
                            } else {
                                g0Var.l();
                            }
                        }
                        g0Var.n();
                        break;
                    case RequestError.NO_DEV_KEY /* 41 */:
                        g0Var.e.a = null;
                        if (g0Var.g.a.length() > 0) {
                            if (g0Var.e()) {
                                g0Var.l();
                            } else {
                                g0Var.m();
                            }
                        }
                        g0Var.n();
                        break;
                    case 42:
                        g0Var.e.a = null;
                        if (g0Var.g.a.length() > 0) {
                            long j = g0Var.f;
                            int i5 = androidx.compose.ui.text.K.c;
                            int i6 = (int) (j & 4294967295L);
                            g0Var.o(i6, i6);
                            break;
                        }
                        break;
                    case 43:
                        if (!y0Var.e) {
                            y0Var.a(kotlin.collections.A.b(new C0998a("\n", 1)));
                            break;
                        } else {
                            y0Var.a.u.invoke(new androidx.compose.ui.text.input.l(y0Var.l));
                            break;
                        }
                    case 44:
                        if (!y0Var.e) {
                            y0Var.a(kotlin.collections.A.b(new C0998a("\t", 1)));
                            break;
                        } else {
                            ((kotlin.jvm.internal.F) obj2).a = false;
                            break;
                        }
                    case 45:
                        androidx.compose.foundation.text.Q0 q02 = y0Var.h;
                        if (q02 != null) {
                            q02.a(androidx.compose.ui.text.input.A.a(g0Var.h, g0Var.g, g0Var.f, 4));
                        }
                        androidx.compose.foundation.text.Q0 q03 = y0Var.h;
                        if (q03 != null) {
                            androidx.work.impl.model.v vVar2 = q03.a;
                            if (vVar2 != null && (vVar = (androidx.work.impl.model.v) vVar2.b) != null) {
                                q03.a = vVar;
                                q03.c -= ((androidx.compose.ui.text.input.A) vVar2.c).a.a.length();
                                q03.b = new androidx.work.impl.model.v(3, q03.b, (androidx.compose.ui.text.input.A) vVar2.c);
                                a = (androidx.compose.ui.text.input.A) vVar.c;
                            }
                            if (a != null) {
                                y0Var.k.invoke(a);
                                break;
                            }
                        }
                        break;
                    case 46:
                        androidx.compose.foundation.text.Q0 q04 = y0Var.h;
                        if (q04 != null) {
                            androidx.work.impl.model.v vVar3 = q04.b;
                            if (vVar3 != null) {
                                q04.b = (androidx.work.impl.model.v) vVar3.b;
                                androidx.compose.ui.text.input.A a2 = (androidx.compose.ui.text.input.A) vVar3.c;
                                q04.a = new androidx.work.impl.model.v(3, q04.a, a2);
                                q04.c = a2.a.a.length() + q04.c;
                                a = (androidx.compose.ui.text.input.A) vVar3.c;
                            }
                            if (a != null) {
                                y0Var.k.invoke(a);
                                break;
                            }
                        }
                        break;
                }
                break;
            default:
                InterfaceC0819s interfaceC0819s = (InterfaceC0819s) obj;
                C0813o0 c0813o0 = (C0813o0) obj3;
                if (c0813o0.e == i2) {
                    androidx.collection.C c = (androidx.collection.C) obj2;
                    if (Intrinsics.b(c, c0813o0.f) && (interfaceC0819s instanceof C0833w)) {
                        long[] jArr = c.a;
                        int length3 = jArr.length - 2;
                        if (length3 >= 0) {
                            int i7 = 0;
                            while (true) {
                                long j2 = jArr[i7];
                                if ((((~j2) << 7) & j2 & (-9187201950435737472L)) != -9187201950435737472L) {
                                    int i8 = 8;
                                    int i9 = 8 - ((~(i7 - length3)) >>> 31);
                                    int i10 = 0;
                                    while (i10 < i9) {
                                        if ((j2 & 255) < 128) {
                                            int i11 = (i7 << 3) + i10;
                                            Object obj4 = c.b[i11];
                                            boolean z3 = c.c[i11] != i2;
                                            if (z3) {
                                                i = i8;
                                                C0833w c0833w = (C0833w) interfaceC0819s;
                                                F4.d(c0833w.g, obj4, c0813o0);
                                                if (obj4 instanceof androidx.compose.runtime.E) {
                                                    androidx.compose.runtime.E e = (androidx.compose.runtime.E) obj4;
                                                    z = z3;
                                                    if (!c0833w.g.c(e)) {
                                                        F4.e(c0833w.j, e);
                                                    }
                                                    androidx.collection.I i12 = c0813o0.g;
                                                    if (i12 != null) {
                                                        i12.h(obj4);
                                                    }
                                                } else {
                                                    z = z3;
                                                }
                                            } else {
                                                z = z3;
                                                i = i8;
                                            }
                                            if (z) {
                                                c.f(i11);
                                            }
                                        } else {
                                            i = i8;
                                        }
                                        j2 >>= i;
                                        i10++;
                                        i8 = i;
                                    }
                                    if (i9 == i8) {
                                    }
                                }
                                if (i7 != length3) {
                                    i7++;
                                }
                            }
                        }
                    }
                }
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ P0(Object obj, int i, Object obj2, int i2) {
        super(1);
        this.a = i2;
        this.c = obj;
        this.b = i;
        this.d = obj2;
    }
}
