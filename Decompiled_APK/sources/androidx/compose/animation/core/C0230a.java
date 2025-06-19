package androidx.compose.animation.core;

import androidx.compose.foundation.gestures.C0343p;
import androidx.compose.foundation.text.C0492h0;
import androidx.compose.foundation.text.C0550y;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.W0;
import androidx.compose.ui.layout.AbstractC0897s;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.animation.core.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0230a extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0230a(Object obj, Object obj2, Object obj3, Object obj4, int i) {
        super(1);
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
        this.e = obj4;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        boolean z;
        androidx.compose.ui.layout.r rVarH;
        switch (this.a) {
            case 0:
                C0254m c0254m = (C0254m) obj;
                C0238e c0238e = (C0238e) this.b;
                AbstractC0240f.s(c0254m, c0238e.c);
                androidx.compose.runtime.L0 l0 = (androidx.compose.runtime.L0) c0254m.e;
                Object objA = C0238e.a(c0238e, l0.getValue());
                boolean zB = Intrinsics.b(objA, l0.getValue());
                Function1 function1 = (Function1) this.d;
                if (!zB) {
                    ((androidx.compose.runtime.L0) c0238e.c.b).setValue(objA);
                    ((androidx.compose.runtime.L0) ((C0258o) this.c).b).setValue(objA);
                    if (function1 != null) {
                        function1.invoke(c0238e);
                    }
                    c0254m.a();
                    ((kotlin.jvm.internal.F) this.e).a = true;
                } else if (function1 != null) {
                    function1.invoke(c0238e);
                }
                return Unit.a;
            case 1:
                long jLongValue = ((Number) obj).longValue();
                W0 w0 = (W0) ((InterfaceC0773a0) this.b).getValue();
                long jLongValue2 = w0 != null ? ((Number) w0.getValue()).longValue() : jLongValue;
                N n = (N) this.c;
                long j = n.c;
                androidx.compose.runtime.collection.b bVar = n.a;
                kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.e;
                int i = 0;
                kotlin.jvm.internal.G g = (kotlin.jvm.internal.G) this.d;
                if (j == Long.MIN_VALUE || g.a != AbstractC0240f.n(c.getCoroutineContext())) {
                    n.c = jLongValue;
                    int i2 = bVar.c;
                    if (i2 > 0) {
                        Object[] objArr = bVar.a;
                        int i3 = 0;
                        do {
                            ((J) objArr[i3]).g = true;
                            i3++;
                        } while (i3 < i2);
                    }
                    g.a = AbstractC0240f.n(c.getCoroutineContext());
                }
                float f = g.a;
                if (f == DefinitionKt.NO_Float_VALUE) {
                    int i4 = bVar.c;
                    if (i4 > 0) {
                        Object[] objArr2 = bVar.a;
                        do {
                            J j2 = (J) objArr2[i];
                            ((androidx.compose.runtime.L0) j2.d).setValue(j2.e.c);
                            j2.g = true;
                            i++;
                        } while (i < i4);
                    }
                } else {
                    long j3 = (long) ((jLongValue2 - n.c) / f);
                    int i5 = bVar.c;
                    if (i5 > 0) {
                        Object[] objArr3 = bVar.a;
                        z = true;
                        int i6 = 0;
                        do {
                            J j4 = (J) objArr3[i6];
                            if (!j4.f) {
                                ((androidx.compose.runtime.L0) j4.i.b).setValue(Boolean.FALSE);
                                if (j4.g) {
                                    j4.g = false;
                                    j4.h = j3;
                                }
                                long j5 = j3 - j4.h;
                                ((androidx.compose.runtime.L0) j4.d).setValue(j4.e.f(j5));
                                j4.f = j4.e.e(j5);
                            }
                            if (!j4.f) {
                                z = false;
                            }
                            i6++;
                        } while (i6 < i5);
                    } else {
                        z = true;
                    }
                    ((androidx.compose.runtime.L0) n.d).setValue(Boolean.valueOf(!z));
                }
                return Unit.a;
            case 2:
                C0254m c0254m2 = (C0254m) obj;
                float fFloatValue = ((Number) ((androidx.compose.runtime.L0) c0254m2.e).getValue()).floatValue();
                kotlin.jvm.internal.G g2 = (kotlin.jvm.internal.G) this.b;
                float f2 = fFloatValue - g2.a;
                float fA = ((androidx.compose.foundation.gestures.G0) this.c).a(f2);
                g2.a = ((Number) ((androidx.compose.runtime.L0) c0254m2.e).getValue()).floatValue();
                ((kotlin.jvm.internal.G) this.d).a = ((Number) c0254m2.a.b.invoke(c0254m2.f)).floatValue();
                if (Math.abs(f2 - fA) > 0.5f) {
                    c0254m2.a();
                }
                ((C0343p) this.e).getClass();
                return Unit.a;
            case 3:
                C0492h0 c0492h0 = (C0492h0) this.b;
                if (c0492h0.b()) {
                    kotlin.jvm.internal.J j6 = new kotlin.jvm.internal.J();
                    androidx.activity.compose.g gVar = new androidx.activity.compose.g(c0492h0.d, c0492h0.t, j6, 12);
                    androidx.compose.ui.text.input.B b = (androidx.compose.ui.text.input.B) this.c;
                    androidx.compose.ui.text.input.u uVar = b.a;
                    uVar.e((androidx.compose.ui.text.input.A) this.d, (androidx.compose.ui.text.input.m) this.e, gVar, c0492h0.u);
                    androidx.compose.ui.text.input.H h = new androidx.compose.ui.text.input.H(b, uVar);
                    b.b.set(h);
                    j6.a = h;
                    c0492h0.e = h;
                }
                return new C0550y();
            default:
                androidx.compose.ui.layout.r rVar = (androidx.compose.ui.layout.r) obj;
                androidx.compose.ui.geometry.c cVarF = AbstractC0897s.f(rVar);
                ((androidx.compose.runtime.F0) this.b).j(cVarF.a);
                ((androidx.compose.runtime.F0) this.c).j(cVarF.b);
                androidx.compose.ui.layout.r rVarH2 = rVar.H();
                androidx.compose.ui.layout.r rVarH3 = (rVarH2 == null || (rVarH = rVarH2.H()) == null) ? null : rVarH.h();
                if (rVarH3 != null) {
                    androidx.compose.ui.geometry.c cVarF2 = AbstractC0897s.f(rVarH3);
                    ((androidx.compose.runtime.F0) this.d).j(cVarF2.c);
                    ((androidx.compose.runtime.F0) this.e).j(cVarF2.b);
                }
                return Unit.a;
        }
    }
}
