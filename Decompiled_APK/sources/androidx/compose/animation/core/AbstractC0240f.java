package androidx.compose.animation.core;

import androidx.compose.animation.C0278e;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.C0972v0;
import com.comscore.streaming.ContentType;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.animation.core.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0240f {
    public static final C0260p a = new C0260p(Float.POSITIVE_INFINITY);
    public static final C0262q b = new C0262q(Float.POSITIVE_INFINITY, Float.POSITIVE_INFINITY);
    public static final r c = new r(Float.POSITIVE_INFINITY, Float.POSITIVE_INFINITY, Float.POSITIVE_INFINITY);
    public static final C0265s d = new C0265s(Float.POSITIVE_INFINITY, Float.POSITIVE_INFINITY, Float.POSITIVE_INFINITY, Float.POSITIVE_INFINITY);
    public static final C0260p e = new C0260p(Float.NEGATIVE_INFINITY);
    public static final C0262q f = new C0262q(Float.NEGATIVE_INFINITY, Float.NEGATIVE_INFINITY);
    public static final r g = new r(Float.NEGATIVE_INFINITY, Float.NEGATIVE_INFINITY, Float.NEGATIVE_INFINITY);
    public static final C0265s h = new C0265s(Float.NEGATIVE_INFINITY, Float.NEGATIVE_INFINITY, Float.NEGATIVE_INFINITY, Float.NEGATIVE_INFINITY);

    public static C0238e a(float f2) {
        return new C0238e(Float.valueOf(f2), M0.a, Float.valueOf(0.01f), 8);
    }

    public static C0258o b(float f2, float f3, int i) {
        if ((i & 2) != 0) {
            f3 = DefinitionKt.NO_Float_VALUE;
        }
        return new C0258o(M0.a, Float.valueOf(f2), new C0260p(f3), Long.MIN_VALUE, Long.MIN_VALUE, false);
    }

    public static final Object c(float f2, float f3, float f4, InterfaceC0256n interfaceC0256n, Function2 function2, kotlin.coroutines.jvm.internal.i iVar) {
        L0 l0 = M0.a;
        Float f5 = new Float(f2);
        Float f6 = new Float(f3);
        C0260p c0260p = new C0260p(new Float(f4).floatValue());
        Object objD = d(new C0258o(l0, f5, c0260p, 56), new C0270u0(interfaceC0256n, l0, f5, f6, c0260p), Long.MIN_VALUE, new androidx.camera.lifecycle.f(function2), iVar);
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (objD != aVar) {
            objD = Unit.a;
        }
        return objD == aVar ? objD : Unit.a;
    }

    /* JADX WARN: Removed duplicated region for block: B:67:0x0169  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x0178  */
    /* JADX WARN: Removed duplicated region for block: B:8:0x0018  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object d(androidx.compose.animation.core.C0258o r22, androidx.compose.animation.core.InterfaceC0250k r23, long r24, kotlin.jvm.functions.Function1 r26, kotlin.coroutines.jvm.internal.c r27) {
        /*
            Method dump skipped, instructions count: 388
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.animation.core.AbstractC0240f.d(androidx.compose.animation.core.o, androidx.compose.animation.core.k, long, kotlin.jvm.functions.Function1, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static /* synthetic */ Object e(float f2, float f3, InterfaceC0256n interfaceC0256n, Function2 function2, kotlin.coroutines.jvm.internal.i iVar, int i) {
        if ((i & 8) != 0) {
            interfaceC0256n = q(7, null);
        }
        return c(f2, f3, DefinitionKt.NO_Float_VALUE, interfaceC0256n, function2, iVar);
    }

    public static final Object f(C0258o c0258o, C0276z c0276z, boolean z, Function1 function1, kotlin.coroutines.jvm.internal.c cVar) {
        Object objD = d(c0258o, new C0275y(c0276z, c0258o.a, ((androidx.compose.runtime.L0) c0258o.b).getValue(), c0258o.c), z ? c0258o.d : Long.MIN_VALUE, function1, cVar);
        return objD == kotlin.coroutines.intrinsics.a.a ? objD : Unit.a;
    }

    public static final J g(N n, float f2, float f3, I i, String str, InterfaceC0806l interfaceC0806l, int i2, int i3) {
        if ((i3 & 8) != 0) {
            str = "FloatAnimation";
        }
        Float fValueOf = Float.valueOf(f2);
        Float fValueOf2 = Float.valueOf(f3);
        int i4 = i2 << 3;
        return j(n, fValueOf, fValueOf2, M0.a, i, str, interfaceC0806l, (i2 & 1022) | (57344 & i4) | (i4 & 458752), 0);
    }

    public static final Object h(C0258o c0258o, Float f2, InterfaceC0256n interfaceC0256n, boolean z, Function1 function1, kotlin.coroutines.jvm.internal.c cVar) {
        Object objD = d(c0258o, new C0270u0(interfaceC0256n, c0258o.a, ((androidx.compose.runtime.L0) c0258o.b).getValue(), f2, c0258o.c), z ? c0258o.d : Long.MIN_VALUE, function1, cVar);
        return objD == kotlin.coroutines.intrinsics.a.a ? objD : Unit.a;
    }

    public static /* synthetic */ Object i(C0258o c0258o, Float f2, InterfaceC0256n interfaceC0256n, boolean z, Function1 function1, kotlin.coroutines.jvm.internal.c cVar, int i) {
        if ((i & 2) != 0) {
            interfaceC0256n = q(7, null);
        }
        InterfaceC0256n interfaceC0256n2 = interfaceC0256n;
        if ((i & 4) != 0) {
            z = false;
        }
        boolean z2 = z;
        if ((i & 8) != 0) {
            function1 = C0266s0.b;
        }
        return h(c0258o, f2, interfaceC0256n2, z2, function1, cVar);
    }

    public static final J j(N n, Number number, Number number2, L0 l0, I i, String str, InterfaceC0806l interfaceC0806l, int i2, int i3) {
        N n2;
        Number number3;
        Number number4;
        I i4;
        C0814p c0814p = (C0814p) interfaceC0806l;
        Object objI = c0814p.I();
        androidx.compose.runtime.V v = C0804k.a;
        if (objI == v) {
            n2 = n;
            number3 = number;
            number4 = number2;
            i4 = i;
            J j = new J(n2, number3, number4, l0, i4);
            c0814p.i0(j);
            objI = j;
        } else {
            n2 = n;
            number3 = number;
            number4 = number2;
            i4 = i;
        }
        J j2 = (J) objI;
        boolean z = true;
        boolean z2 = ((((i2 & ContentType.LONG_FORM_ON_DEMAND) ^ 48) > 32 && c0814p.h(number3)) || (i2 & 48) == 32) | ((((i2 & 896) ^ 384) > 256 && c0814p.h(number4)) || (i2 & 384) == 256);
        if ((((57344 & i2) ^ 24576) <= 16384 || !c0814p.h(i4)) && (i2 & 24576) != 16384) {
            z = false;
        }
        boolean z3 = z2 | z;
        Object objI2 = c0814p.I();
        if (z3 || objI2 == v) {
            objI2 = new O(number3, j2, number4, i4);
            c0814p.i0(objI2);
        }
        C0776c.i((Function0) objI2, c0814p);
        boolean zH = c0814p.h(n2);
        Object objI3 = c0814p.I();
        if (zH || objI3 == v) {
            objI3 = new C0278e(2, n2, j2);
            c0814p.i0(objI3);
        }
        C0776c.d(j2, (Function1) objI3, c0814p);
        return j2;
    }

    public static final AbstractC0267t k(AbstractC0267t abstractC0267t) {
        AbstractC0267t abstractC0267tC = abstractC0267t.c();
        int iB = abstractC0267tC.b();
        for (int i = 0; i < iB; i++) {
            abstractC0267tC.e(abstractC0267t.a(i), i);
        }
        return abstractC0267tC;
    }

    public static C0258o l(C0258o c0258o, float f2, float f3, int i) {
        if ((i & 1) != 0) {
            f2 = ((Number) ((androidx.compose.runtime.L0) c0258o.b).getValue()).floatValue();
        }
        if ((i & 2) != 0) {
            f3 = ((C0260p) c0258o.c).a;
        }
        return new C0258o(c0258o.a, Float.valueOf(f2), new C0260p(f3), c0258o.d, c0258o.e, c0258o.f);
    }

    public static final void m(C0254m c0254m, long j, float f2, InterfaceC0250k interfaceC0250k, C0258o c0258o, Function1 function1) {
        long jB = f2 == DefinitionKt.NO_Float_VALUE ? interfaceC0250k.b() : (long) ((j - c0254m.c) / f2);
        c0254m.g = j;
        ((androidx.compose.runtime.L0) c0254m.e).setValue(interfaceC0250k.f(jB));
        c0254m.f = interfaceC0250k.d(jB);
        if (interfaceC0250k.e(jB)) {
            c0254m.h = c0254m.g;
            ((androidx.compose.runtime.L0) c0254m.i).setValue(Boolean.FALSE);
        }
        s(c0254m, c0258o);
        function1.invoke(c0254m);
    }

    public static final float n(CoroutineContext coroutineContext) {
        androidx.compose.ui.r rVar = (androidx.compose.ui.r) coroutineContext.get(androidx.compose.ui.b.p);
        float fD = rVar != null ? rVar.D() : 1.0f;
        if (fD >= DefinitionKt.NO_Float_VALUE) {
            return fD;
        }
        throw new IllegalStateException("negative scale factor");
    }

    public static I o(A a2, int i) {
        return new I(a2, 1, 0);
    }

    public static final N p(String str, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        Object objI = c0814p.I();
        if (objI == C0804k.a) {
            objI = new N();
            c0814p.i0(objI);
        }
        N n = (N) objI;
        n.a(c0814p, 0);
        return n;
    }

    public static C0253l0 q(int i, Object obj) {
        float f2 = (i & 2) != 0 ? 1500.0f : 400.0f;
        if ((i & 4) != 0) {
            obj = null;
        }
        return new C0253l0(1.0f, f2, obj);
    }

    public static K0 r(int i, int i2, B b2, int i3) {
        if ((i3 & 1) != 0) {
            i = 300;
        }
        if ((i3 & 2) != 0) {
            i2 = 0;
        }
        if ((i3 & 4) != 0) {
            b2 = C.a;
        }
        return new K0(i, i2, b2);
    }

    public static final void s(C0254m c0254m, C0258o c0258o) {
        ((androidx.compose.runtime.L0) c0258o.b).setValue(((androidx.compose.runtime.L0) c0254m.e).getValue());
        AbstractC0267t abstractC0267t = c0258o.c;
        AbstractC0267t abstractC0267t2 = c0254m.f;
        int iB = abstractC0267t.b();
        for (int i = 0; i < iB; i++) {
            abstractC0267t.e(abstractC0267t2.a(i), i);
        }
        c0258o.e = c0254m.h;
        c0258o.d = c0254m.g;
        c0258o.f = ((Boolean) ((androidx.compose.runtime.L0) c0254m.i).getValue()).booleanValue();
    }

    public static final Object t(Function1 function1, kotlin.coroutines.jvm.internal.c cVar) {
        if (cVar.getContext().get(C0972v0.a) == null) {
            return C0776c.r(cVar.getContext()).P(function1, cVar);
        }
        throw new ClassCastException();
    }
}
