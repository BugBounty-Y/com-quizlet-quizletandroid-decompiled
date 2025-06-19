package androidx.compose.material3;

import androidx.compose.animation.C0281h;
import androidx.compose.animation.core.AbstractC0248j;
import androidx.compose.animation.core.C0238e;
import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.C0367i0;
import androidx.compose.foundation.gestures.EnumC0320d0;
import androidx.compose.foundation.layout.C0418x;
import androidx.compose.material3.internal.AbstractC0646j;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AbstractC0955m0;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.V5;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public abstract class A2 {
    public static final float a = 48;
    public static final float b = 24;
    public static final long c = androidx.compose.ui.graphics.F.i(0.5f, DefinitionKt.NO_Float_VALUE);

    /* JADX WARN: Removed duplicated region for block: B:104:0x0209  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x0149  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x014c  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x0157  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x0169  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x0197  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x019a  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x01a3 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:99:0x01a5  */
    /* JADX WARN: Type inference failed for: r0v26, types: [java.lang.Object, java.util.Map] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(kotlin.jvm.functions.Function0 r28, androidx.compose.ui.q r29, androidx.compose.material3.F3 r30, float r31, androidx.compose.ui.graphics.V r32, long r33, long r35, float r37, long r38, androidx.compose.runtime.internal.d r40, androidx.compose.material3.C0602d0 r41, androidx.compose.material3.B2 r42, androidx.compose.runtime.internal.d r43, androidx.compose.runtime.InterfaceC0806l r44, int r45) {
        /*
            Method dump skipped, instructions count: 608
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.material3.A2.a(kotlin.jvm.functions.Function0, androidx.compose.ui.q, androidx.compose.material3.F3, float, androidx.compose.ui.graphics.V, long, long, float, long, androidx.compose.runtime.internal.d, androidx.compose.material3.d0, androidx.compose.material3.B2, androidx.compose.runtime.internal.d, androidx.compose.runtime.l, int):void");
    }

    public static final void b(C0238e c0238e, kotlinx.coroutines.C c2, Function0 function0, Function1 function1, androidx.compose.ui.q qVar, F3 f3, float f, androidx.compose.ui.graphics.V v, long j, long j2, float f2, androidx.compose.runtime.internal.d dVar, Function2 function2, androidx.compose.runtime.internal.d dVar2, InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p;
        C0418x c0418x = C0418x.a;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-1676960531);
        int i2 = i | (c0814p2.h(c0238e) ? 32 : 16) | (c0814p2.h(c2) ? 256 : 128) | (c0814p2.h(function0) ? 2048 : 1024) | (c0814p2.h(function1) ? 16384 : 8192) | (c0814p2.f(qVar) ? 131072 : 65536) | (c0814p2.f(f3) ? 1048576 : 524288) | (c0814p2.c(f) ? 8388608 : 4194304) | (c0814p2.f(v) ? 67108864 : 33554432) | (c0814p2.e(j) ? 536870912 : 268435456);
        int i3 = (c0814p2.e(j2) ? 4 : 2) | (c0814p2.c(f2) ? 32 : 16) | (c0814p2.h(dVar) ? 256 : 128) | (c0814p2.h(function2) ? 2048 : 1024) | (c0814p2.h(dVar2) ? 16384 : 8192);
        if ((i2 & 306783379) == 306783378 && (i3 & 9363) == 9362 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            c0814p2.S();
            if ((i & 1) != 0 && !c0814p2.w()) {
                c0814p2.Q();
            }
            c0814p2.q();
            String strG = AbstractC0646j.g(c0814p2, R.string.m3c_bottom_sheet_pane_title);
            androidx.compose.ui.q qVarC = androidx.compose.foundation.layout.K0.c(androidx.compose.foundation.layout.K0.q(c0418x.a(qVar, androidx.compose.ui.b.b), DefinitionKt.NO_Float_VALUE, f, 1), 1.0f);
            int i4 = (i2 & 3670016) ^ 1572864;
            boolean z = (i4 > 1048576 && c0814p2.f(f3)) || (i2 & 1572864) == 1048576;
            Object objI = c0814p2.I();
            Object obj = C0804k.a;
            if (z || objI == obj) {
                androidx.compose.animation.core.K0 k0 = E3.a;
                objI = new C3(f3, function1);
                c0814p2.i0(objI);
            }
            androidx.compose.ui.q qVarA = androidx.compose.ui.input.nestedscroll.f.a(qVarC, (androidx.compose.ui.input.nestedscroll.a) objI, null);
            androidx.work.impl.model.t tVar = f3.b;
            EnumC0320d0 enumC0320d0 = EnumC0320d0.a;
            boolean z2 = (i4 > 1048576 && c0814p2.f(f3)) || (i2 & 1572864) == 1048576;
            Object objI2 = c0814p2.I();
            if (z2 || objI2 == obj) {
                objI2 = new C0281h(f3, 17);
                c0814p2.i0(objI2);
            }
            androidx.compose.ui.q qVarD = AbstractC0646j.d(qVarA, tVar, enumC0320d0, (Function2) objI2);
            androidx.compose.material.r rVar = (androidx.compose.material.r) f3.b.f;
            boolean zC = f3.c();
            boolean z3 = ((androidx.compose.runtime.L0) ((InterfaceC0773a0) f3.b.l)).getValue() != null;
            boolean z4 = (i2 & 57344) == 16384;
            Object objI3 = c0814p2.I();
            if (z4 || objI3 == obj) {
                objI3 = new C0745v2(function1, null);
                c0814p2.i0(objI3);
            }
            androidx.compose.ui.q qVarA2 = androidx.compose.foundation.gestures.U.a(qVarD, rVar, enumC0320d0, zC, z3, (kotlin.jvm.functions.c) objI3, 168);
            boolean zF = c0814p2.f(strG);
            Object objI4 = c0814p2.I();
            if (zF || objI4 == obj) {
                objI4 = new C0367i0(strG, 8);
                c0814p2.i0(objI4);
            }
            androidx.compose.ui.q qVarA3 = androidx.compose.ui.semantics.m.a(qVarA2, false, (Function1) objI4);
            boolean z5 = ((i2 & ContentType.LONG_FORM_ON_DEMAND) == 32 || c0814p2.h(c0238e)) | ((i4 > 1048576 && c0814p2.f(f3)) || (i2 & 1572864) == 1048576);
            Object objI5 = c0814p2.I();
            if (z5 || objI5 == obj) {
                objI5 = new androidx.compose.foundation.text.selection.n0(5, f3, c0238e);
                c0814p2.i0(objI5);
            }
            int i5 = i2 >> 21;
            int i6 = i3 << 9;
            c0814p = c0814p2;
            AbstractC0594b4.a(androidx.compose.ui.graphics.F.p(qVarA3, (Function1) objI5), v, j, j2, f2, DefinitionKt.NO_Float_VALUE, null, androidx.compose.runtime.internal.e.e(-692668920, new androidx.compose.foundation.lazy.grid.n(function2, c0238e, dVar, f3, function0, c2, dVar2), c0814p2), c0814p, (i5 & 896) | (i5 & ContentType.LONG_FORM_ON_DEMAND) | 12582912 | (i6 & 7168) | (i6 & 57344), 96);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C0763y2(c0238e, c2, function0, function1, qVar, f3, f, v, j, j2, f2, dVar, function2, dVar2, i);
        }
    }

    public static final void c(long j, Function0 function0, boolean z, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        boolean z2;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(951870469);
        if ((i & 6) == 0) {
            i2 = (c0814p.e(j) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(function0) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.g(z) ? 256 : 128;
        }
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else if (j != 16) {
            androidx.compose.runtime.W0 w0B = AbstractC0248j.b(z ? 1.0f : DefinitionKt.NO_Float_VALUE, new androidx.compose.animation.core.K0(0, (androidx.compose.animation.core.B) null, 7), null, null, c0814p, 48, 28);
            String strG = AbstractC0646j.g(c0814p, R.string.close_sheet);
            c0814p.X(-1785653838);
            androidx.compose.runtime.V v = C0804k.a;
            androidx.compose.ui.q qVarA = androidx.compose.ui.n.b;
            if (z) {
                int i3 = i2 & ContentType.LONG_FORM_ON_DEMAND;
                boolean z3 = i3 == 32;
                Object objI = c0814p.I();
                if (z3 || objI == v) {
                    objI = new C0769z2(function0, null);
                    c0814p.i0(objI);
                }
                androidx.compose.ui.q qVarA2 = androidx.compose.ui.input.pointer.v.a(qVarA, function0, (Function2) objI);
                boolean zF = (i3 == 32) | c0814p.f(strG);
                Object objI2 = c0814p.I();
                if (zF || objI2 == v) {
                    objI2 = new androidx.compose.material.W(strG, function0, 1);
                    c0814p.i0(objI2);
                }
                qVarA = androidx.compose.ui.semantics.m.a(qVarA2, true, (Function1) objI2);
                z2 = false;
            } else {
                z2 = false;
            }
            c0814p.p(z2);
            androidx.compose.ui.q qVarG = androidx.compose.foundation.layout.K0.c.g(qVarA);
            boolean zF2 = c0814p.f(w0B) | ((i2 & 14) == 4);
            Object objI3 = c0814p.I();
            if (zF2 || objI3 == v) {
                objI3 = new androidx.compose.material.S(j, w0B, 1);
                c0814p.i0(objI3);
            }
            AbstractC0460p.b(qVarG, (Function1) objI3, c0814p, 0);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.compose.material.T(j, function0, z, i, 1);
        }
    }

    public static final float d(androidx.compose.ui.graphics.S s, float f) {
        float fD = androidx.compose.ui.geometry.e.d(s.r);
        if (Float.isNaN(fD) || fD == DefinitionKt.NO_Float_VALUE) {
            return 1.0f;
        }
        return 1.0f - (V5.c(DefinitionKt.NO_Float_VALUE, Math.min(s.s.a() * a, fD), f) / fD);
    }

    public static final float e(androidx.compose.ui.graphics.S s, float f) {
        float fB = androidx.compose.ui.geometry.e.b(s.r);
        if (Float.isNaN(fB) || fB == DefinitionKt.NO_Float_VALUE) {
            return 1.0f;
        }
        return 1.0f - (V5.c(DefinitionKt.NO_Float_VALUE, Math.min(s.s.a() * b, fB), f) / fB);
    }

    public static final F3 f(boolean z, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        G3 g3 = G3.a;
        if ((i & 1) != 0) {
            z = false;
        }
        if ((i & 2) != 0) {
            function1 = C0736u.q;
        }
        androidx.compose.animation.core.K0 k0 = E3.a;
        C0814p c0814p = (C0814p) interfaceC0806l;
        androidx.compose.ui.unit.b bVar = (androidx.compose.ui.unit.b) c0814p.j(AbstractC0955m0.f);
        Object[] objArr = {Boolean.valueOf(z), function1, Boolean.FALSE};
        C0602d0 c0602d0 = C0602d0.B;
        androidx.compose.foundation.pager.q qVar = new androidx.compose.foundation.pager.q(z, bVar, function1, 1);
        com.quizlet.data.repository.explanations.myexplanations.a aVar = androidx.compose.runtime.saveable.m.a;
        com.quizlet.data.repository.explanations.myexplanations.a aVar2 = new com.quizlet.data.repository.explanations.myexplanations.a(c0602d0, false, qVar, 3);
        boolean zG = c0814p.g(z) | c0814p.f(bVar) | c0814p.f(function1) | c0814p.g(false);
        Object objI = c0814p.I();
        if (zG || objI == C0804k.a) {
            objI = new D3(z, bVar, g3, function1);
            c0814p.i0(objI);
        }
        return (F3) com.google.android.gms.internal.mlkit_vision_barcode.L4.d(objArr, aVar2, (Function0) objI, c0814p, 0, 4);
    }
}
