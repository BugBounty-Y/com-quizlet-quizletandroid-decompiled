package com.google.android.gms.internal.mlkit_vision_common;

import androidx.compose.foundation.AbstractC0460p;
import androidx.compose.foundation.C0555x;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0409s;
import androidx.compose.material3.AbstractC0590b0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_barcode.Z4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3561x4;
import com.google.firebase.components.DependencyCycleException;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.x4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3561x4 {
    public static final void a(com.quizlet.learn.data.onboarding.m mVar, androidx.compose.ui.q qVar, boolean z, boolean z2, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        boolean z3;
        Function0 function02;
        long j;
        long jE;
        com.quizlet.learn.data.onboarding.m mVar2 = mVar;
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1280884522);
        if ((i & 6) == 0) {
            i2 = (c0814p.f(mVar2) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            z3 = z;
            i2 |= c0814p.g(z3) ? 256 : 128;
        } else {
            z3 = z;
        }
        if ((i & 3072) == 0) {
            i2 |= c0814p.g(z2) ? 2048 : 1024;
        }
        if ((i & 24576) == 0) {
            function02 = function0;
            i2 |= c0814p.h(function02) ? 16384 : 8192;
        } else {
            function02 = function0;
        }
        if ((i2 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.runtime.V v = C0804k.a;
            c0814p.X(-705787088);
            boolean z4 = (i2 & 896) == 256;
            Object objI = c0814p.I();
            if (z4 || objI == v) {
                objI = C0776c.z(Boolean.valueOf(z3));
                c0814p.i0(objI);
            }
            c0814p.p(false);
            if (((Boolean) ((InterfaceC0773a0) objI).getValue()).booleanValue()) {
                c0814p.X(-404476167);
                j = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).e;
                c0814p.p(false);
            } else {
                c0814p.X(-404425730);
                j = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).t;
                c0814p.p(false);
            }
            if (z2) {
                c0814p.X(-404317199);
                jE = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).s();
                c0814p.p(false);
            } else {
                c0814p.X(-404259539);
                jE = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.e();
                c0814p.p(false);
            }
            androidx.compose.foundation.layout.A0 a0C = AbstractC0382e.c(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 3);
            com.quizlet.themes.m mVar3 = com.quizlet.themes.m.g;
            C0555x c0555xA = AbstractC0460p.a(j, com.quizlet.themes.m.l);
            mVar3.d();
            androidx.compose.foundation.shape.d dVarA = androidx.compose.foundation.shape.e.a(com.quizlet.ui.resources.designsystem.generated.f.g);
            androidx.compose.foundation.layout.A0 a0 = androidx.compose.material3.L.a;
            long jN = ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).b.n();
            long j2 = C0861v.g;
            androidx.compose.material3.Z z5 = (androidx.compose.material3.Z) c0814p.j(AbstractC0590b0.a);
            androidx.compose.material3.K k = z5.L;
            if (k == null) {
                long j3 = C0861v.f;
                int i3 = androidx.compose.material3.tokens.r.a;
                k = new androidx.compose.material3.K(j3, AbstractC0590b0.c(z5, 26), j3, C0861v.b(AbstractC0590b0.c(z5, 18), 0.38f));
                z5.L = k;
            }
            mVar2 = mVar;
            androidx.compose.material3.Z1.j(function02, qVar, false, dVarA, k.a(jN, j2, j2, j2), c0555xA, a0C, androidx.compose.runtime.internal.e.e(287241544, new com.quizlet.assembly.compose.pills.i(mVar2, jE, 1), c0814p), c0814p, ((i2 >> 12) & 14) | 817889280 | (i2 & ContentType.LONG_FORM_ON_DEMAND));
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.assembly.compose.tabs.c(mVar2, qVar, z3, z2, function0, i);
        }
    }

    public static final void b(final int i, InterfaceC0806l interfaceC0806l, final int i2) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(65740697);
        int i3 = (c0814p.d(i) ? 4 : 2) | i2;
        if ((i3 & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            androidx.compose.ui.q qVarF = AbstractC0460p.f(nVar, ((com.quizlet.themes.b) c0814p.j(com.quizlet.themes.g.a)).D0, androidx.compose.ui.graphics.F.a);
            com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
            mVar.j();
            androidx.compose.ui.q qVarK = androidx.compose.foundation.layout.K0.k(qVarF, com.quizlet.ui.resources.designsystem.generated.h.i);
            androidx.compose.ui.layout.K kE = AbstractC0409s.e(androidx.compose.ui.b.e, false);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVarK);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, kE, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            mVar.g();
            AbstractC0460p.c(Z4.a(i, c0814p, i3 & 14), null, androidx.compose.foundation.layout.K0.k(nVar, com.quizlet.ui.resources.designsystem.generated.h.h), null, null, DefinitionKt.NO_Float_VALUE, null, c0814p, 48, 120);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new Function2(i, i2) { // from class: com.quizlet.learn.ui.onboarding.c
                public final /* synthetic */ int a;

                @Override // kotlin.jvm.functions.Function2
                public final Object invoke(Object obj, Object obj2) {
                    ((Integer) obj2).getClass();
                    int iH = C0776c.H(1);
                    AbstractC3561x4.b(this.a, (InterfaceC0806l) obj, iH);
                    return Unit.a;
                }
            };
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:52:0x00c7  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void c(com.quizlet.learn.data.onboarding.m r20, kotlinx.collections.immutable.e r21, androidx.compose.ui.q r22, kotlin.jvm.functions.Function1 r23, androidx.compose.runtime.InterfaceC0806l r24, int r25) {
        /*
            Method dump skipped, instructions count: 320
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.AbstractC3561x4.c(com.quizlet.learn.data.onboarding.m, kotlinx.collections.immutable.e, androidx.compose.ui.q, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int):void");
    }

    public static void d(ArrayList arrayList) {
        HashMap map = new HashMap(arrayList.size());
        Iterator it2 = arrayList.iterator();
        while (true) {
            int i = 0;
            if (!it2.hasNext()) {
                Iterator it3 = map.values().iterator();
                while (it3.hasNext()) {
                    for (com.google.firebase.components.h hVar : (Set) it3.next()) {
                        for (com.google.firebase.components.j jVar : hVar.a.c) {
                            if (jVar.c == 0) {
                                Set<com.google.firebase.components.h> set = (Set) map.get(new com.google.firebase.components.i(jVar.a, jVar.b == 2));
                                if (set != null) {
                                    for (com.google.firebase.components.h hVar2 : set) {
                                        hVar.b.add(hVar2);
                                        hVar2.c.add(hVar);
                                    }
                                }
                            }
                        }
                    }
                }
                HashSet hashSet = new HashSet();
                Iterator it4 = map.values().iterator();
                while (it4.hasNext()) {
                    hashSet.addAll((Set) it4.next());
                }
                HashSet hashSet2 = new HashSet();
                Iterator it5 = hashSet.iterator();
                while (it5.hasNext()) {
                    com.google.firebase.components.h hVar3 = (com.google.firebase.components.h) it5.next();
                    if (hVar3.c.isEmpty()) {
                        hashSet2.add(hVar3);
                    }
                }
                while (!hashSet2.isEmpty()) {
                    com.google.firebase.components.h hVar4 = (com.google.firebase.components.h) hashSet2.iterator().next();
                    hashSet2.remove(hVar4);
                    i++;
                    Iterator it6 = hVar4.b.iterator();
                    while (it6.hasNext()) {
                        com.google.firebase.components.h hVar5 = (com.google.firebase.components.h) it6.next();
                        hVar5.c.remove(hVar4);
                        if (hVar5.c.isEmpty()) {
                            hashSet2.add(hVar5);
                        }
                    }
                }
                if (i == arrayList.size()) {
                    return;
                }
                ArrayList arrayList2 = new ArrayList();
                Iterator it7 = hashSet.iterator();
                while (it7.hasNext()) {
                    com.google.firebase.components.h hVar6 = (com.google.firebase.components.h) it7.next();
                    if (!hVar6.c.isEmpty() && !hVar6.b.isEmpty()) {
                        arrayList2.add(hVar6.a);
                    }
                }
                throw new DependencyCycleException("Dependency cycle detected: " + Arrays.toString(arrayList2.toArray()));
            }
            com.google.firebase.components.a aVar = (com.google.firebase.components.a) it2.next();
            com.google.firebase.components.h hVar7 = new com.google.firebase.components.h(aVar);
            for (com.google.firebase.components.q qVar : aVar.b) {
                boolean z = aVar.e == 0;
                com.google.firebase.components.i iVar = new com.google.firebase.components.i(qVar, !z);
                if (!map.containsKey(iVar)) {
                    map.put(iVar, new HashSet());
                }
                Set set2 = (Set) map.get(iVar);
                if (!set2.isEmpty() && z) {
                    throw new IllegalArgumentException("Multiple components provide " + qVar + ".");
                }
                set2.add(hVar7);
            }
        }
    }
}
