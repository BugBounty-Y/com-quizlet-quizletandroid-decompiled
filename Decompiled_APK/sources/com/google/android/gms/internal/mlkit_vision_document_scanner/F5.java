package com.google.android.gms.internal.mlkit_vision_document_scanner;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.material3.AbstractC0686n;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import com.comscore.streaming.ContentType;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class F5 {
    public static final /* synthetic */ int a = 0;

    public static final void a(androidx.compose.ui.q qVar, com.quizlet.assembly.compose.menu.s sVar, Function1 function1, long j, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        androidx.compose.ui.q qVar3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-342778589);
        int i2 = i | 6;
        if ((i & 48) == 0) {
            i2 |= (i & 64) == 0 ? c0814p.f(sVar) : c0814p.h(sVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function1) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.e(j) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(function0) ? 16384 : 8192;
        }
        int i3 = i2;
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            qVar3 = qVar;
        } else {
            c0814p.S();
            int i4 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i4 == 0 || c0814p.w()) {
                qVar2 = androidx.compose.ui.n.b;
            } else {
                c0814p.Q();
                qVar2 = qVar;
            }
            c0814p.q();
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(qVar2, "AssemblyDropdownMenu");
            c0814p.X(1516745248);
            boolean z = true;
            boolean z2 = (57344 & i3) == 16384;
            if ((((i3 & ContentType.LONG_FORM_ON_DEMAND) ^ 48) <= 32 || !c0814p.h(sVar)) && (i3 & 48) != 32) {
                z = false;
            }
            boolean z3 = z2 | z;
            Object objI = c0814p.I();
            if (z3 || objI == v) {
                objI = new com.quizlet.assembly.compose.menu.c(function0, sVar, 0);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            d(sVar, j, (Function0) ((kotlin.reflect.f) objI), qVarG, androidx.compose.runtime.internal.e.e(-359640197, new com.quizlet.assembly.compose.input.h(1, sVar, function1, function0, false), c0814p), c0814p, ((i3 >> 3) & 14) | 24576 | ((i3 >> 6) & ContentType.LONG_FORM_ON_DEMAND));
            qVar3 = qVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.b(qVar3, sVar, function1, j, function0, i, 0);
        }
    }

    public static final void b(com.quizlet.assembly.compose.menu.q item, Function1 onItemClick, androidx.compose.ui.n nVar, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.n nVar2;
        Intrinsics.checkNotNullParameter(item, "item");
        Intrinsics.checkNotNullParameter(onItemClick, "onItemClick");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(2101934508);
        int i2 = (c0814p.f(item) ? 4 : 2) | i | (c0814p.h(onItemClick) ? 32 : 16) | 384;
        if ((i2 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            androidx.compose.ui.n nVar3 = androidx.compose.ui.n.b;
            if (item instanceof com.quizlet.assembly.compose.menu.n) {
                c0814p.X(1240273655);
                c0814p.p(false);
            } else {
                if (!(item instanceof com.quizlet.assembly.compose.menu.o)) {
                    throw com.google.android.gms.measurement.internal.Z.j(-514190921, c0814p, false);
                }
                c0814p.X(1240336771);
                G5.b((com.quizlet.assembly.compose.menu.o) item, androidx.compose.foundation.layout.K0.d(nVar3, com.quizlet.themes.m.Z), ((com.quizlet.themes.f) c0814p.j(com.quizlet.themes.w.b)).k, onItemClick, c0814p, (i2 << 6) & 7168);
                c0814p.p(false);
            }
            nVar2 = nVar3;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.lifecycle.compose.e(i, 6, item, onItemClick, nVar2);
        }
    }

    public static final void c(androidx.compose.ui.q qVar, com.quizlet.assembly.compose.menu.s sVar, Function1 function1, long j, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        androidx.compose.ui.q qVar2;
        androidx.compose.ui.q qVar3;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-655409993);
        int i2 = i | 6;
        if ((i & 48) == 0) {
            i2 |= (i & 64) == 0 ? c0814p.f(sVar) : c0814p.h(sVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(function1) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.e(j) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p.h(function0) ? 16384 : 8192;
        }
        int i3 = i2;
        if ((i3 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            qVar3 = qVar;
        } else {
            c0814p.S();
            int i4 = i & 1;
            androidx.compose.runtime.V v = C0804k.a;
            if (i4 == 0 || c0814p.w()) {
                qVar2 = androidx.compose.ui.n.b;
            } else {
                c0814p.Q();
                qVar2 = qVar;
            }
            c0814p.q();
            int i5 = (i3 >> 3) & 14;
            c0814p.X(1962909742);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            float f = com.quizlet.themes.m.Z;
            mVar.w();
            float f2 = (com.quizlet.ui.resources.designsystem.generated.j.f * 2) + com.quizlet.themes.m.h;
            float f3 = com.quizlet.themes.m.Y;
            InterfaceC0773a0 interfaceC0773a0 = sVar.a;
            int size = ((List) ((androidx.compose.runtime.L0) interfaceC0773a0).getValue()).size();
            com.quizlet.assembly.compose.menu.u uVar = (com.quizlet.assembly.compose.menu.u) ((androidx.compose.runtime.L0) sVar.c).getValue();
            c0814p.X(-492940456);
            boolean zF = c0814p.f(uVar) | c0814p.d(size);
            Object objI = c0814p.I();
            if (zF || objI == v) {
                androidx.compose.runtime.L0 l0 = (androidx.compose.runtime.L0) interfaceC0773a0;
                Iterable iterable = (Iterable) l0.getValue();
                ArrayList arrayList = new ArrayList();
                Iterator it2 = iterable.iterator();
                while (it2.hasNext()) {
                    Object next = it2.next();
                    Iterator it3 = it2;
                    if (next instanceof com.quizlet.assembly.compose.menu.o) {
                        arrayList.add(next);
                    }
                    it2 = it3;
                }
                float size2 = f * arrayList.size();
                Iterable iterable2 = (Iterable) l0.getValue();
                ArrayList arrayList2 = new ArrayList();
                Iterator it4 = iterable2.iterator();
                while (it4.hasNext()) {
                    it4.next();
                }
                androidx.compose.ui.unit.e a2 = new androidx.compose.ui.unit.e((arrayList2.size() * f2) + size2);
                androidx.compose.ui.unit.e b = new androidx.compose.ui.unit.e(f3);
                Intrinsics.checkNotNullParameter(a2, "a");
                Intrinsics.checkNotNullParameter(b, "b");
                if (a2.compareTo(b) > 0) {
                    a2 = b;
                }
                objI = C0776c.z(a2);
                c0814p.i0(objI);
            }
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) objI;
            c0814p.p(false);
            c0814p.p(false);
            androidx.compose.ui.q qVarG = androidx.compose.ui.platform.N.G(qVar2, "AssemblyLazyDropdownMenu");
            c0814p.X(-124773100);
            boolean z = ((57344 & i3) == 16384) | ((((i3 & ContentType.LONG_FORM_ON_DEMAND) ^ 48) > 32 && c0814p.h(sVar)) || (i3 & 48) == 32);
            Object objI2 = c0814p.I();
            if (z || objI2 == v) {
                objI2 = new com.quizlet.assembly.compose.menu.c(function0, sVar, 1);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            d(sVar, j, (Function0) ((kotlin.reflect.f) objI2), qVarG, androidx.compose.runtime.internal.e.e(846923535, new com.quizlet.assembly.compose.menu.g((Object) sVar, (Object) function1, (Object) function0, (Object) interfaceC0773a02, 0), c0814p), c0814p, i5 | 24576 | ((i3 >> 6) & ContentType.LONG_FORM_ON_DEMAND));
            qVar3 = qVar2;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.b(qVar3, sVar, function1, j, function0, i, 1);
        }
    }

    public static final void d(com.quizlet.assembly.compose.menu.s sVar, long j, Function0 function0, androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        C0814p c0814p;
        C0814p c0814p2 = (C0814p) interfaceC0806l;
        c0814p2.Z(-112316519);
        if ((i & 6) == 0) {
            i2 = ((i & 8) == 0 ? c0814p2.f(sVar) : c0814p2.h(sVar) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p2.e(j) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p2.h(function0) ? 256 : 128;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p2.f(qVar) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            i2 |= c0814p2.h(dVar) ? 16384 : 8192;
        }
        if ((i2 & 9363) == 9362 && c0814p2.x()) {
            c0814p2.Q();
            c0814p = c0814p2;
        } else {
            androidx.compose.runtime.B b = com.quizlet.themes.g.a;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(qVar, ((com.quizlet.themes.b) c0814p2.j(b)).b.g(), androidx.compose.ui.graphics.F.a);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            androidx.compose.ui.q qVarM = androidx.compose.foundation.layout.K0.m(qVarF, com.quizlet.themes.m.V, com.quizlet.themes.m.X, com.quizlet.themes.m.W, com.quizlet.themes.m.Y);
            float f = com.quizlet.themes.m.h;
            long j2 = ((com.quizlet.themes.b) c0814p2.j(b)).M;
            mVar.e();
            androidx.compose.ui.q qVarA = androidx.compose.animation.H.a(AbstractC0460p.g(qVarM, f, j2, androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.f)), null, 3);
            Intrinsics.checkNotNullParameter(sVar, "<this>");
            c0814p = c0814p2;
            AbstractC0686n.a(((androidx.compose.runtime.L0) sVar.c).getValue() != com.quizlet.assembly.compose.menu.u.b, function0, qVarA, j, null, null, null, 0L, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, dVar, c0814p, ((i2 >> 3) & ContentType.LONG_FORM_ON_DEMAND) | ((i2 << 6) & 7168), (i2 >> 9) & ContentType.LONG_FORM_ON_DEMAND, 2032);
            if (K5.a(sVar)) {
                function0.invoke();
            }
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.menu.a(sVar, j, function0, qVar, dVar, i);
        }
    }
}
