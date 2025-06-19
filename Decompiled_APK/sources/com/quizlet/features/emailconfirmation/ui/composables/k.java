package com.quizlet.features.emailconfirmation.ui.composables;

import androidx.compose.material3.G;
import androidx.compose.runtime.F0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.layout.AbstractC0882c;
import androidx.compose.ui.layout.AbstractC0897s;
import androidx.compose.ui.layout.C0893n;
import androidx.compose.ui.layout.J;
import androidx.compose.ui.layout.K;
import androidx.compose.ui.layout.L;
import androidx.compose.ui.layout.M;
import androidx.compose.ui.layout.W;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.NoSuchElementException;
import kotlin.Pair;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class k implements K {
    public final /* synthetic */ int a;
    public final /* synthetic */ InterfaceC0773a0 b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ InterfaceC0773a0 e;

    public /* synthetic */ k(InterfaceC0773a0 interfaceC0773a0, androidx.constraintlayout.compose.j jVar, androidx.constraintlayout.compose.i iVar, InterfaceC0773a0 interfaceC0773a02, int i) {
        this.a = i;
        this.b = interfaceC0773a0;
        this.c = jVar;
        this.d = iVar;
        this.e = interfaceC0773a02;
    }

    @Override // androidx.compose.ui.layout.K
    /* renamed from: measure-3p2s80s */
    public final L mo1measure3p2s80s(M m, List list, long j) {
        switch (this.a) {
            case 0:
                LinkedHashMap linkedHashMap = new LinkedHashMap();
                this.b.getValue();
                long jF = ((androidx.constraintlayout.compose.j) this.c).f(j, m.getLayoutDirection(), (androidx.constraintlayout.compose.i) this.d, list, linkedHashMap);
                this.e.getValue();
                return m.n0((int) (jF >> 32), (int) (jF & 4294967295L), V.c(), new j((androidx.constraintlayout.compose.j) this.c, list, linkedHashMap, 0));
            case 1:
                LinkedHashMap linkedHashMap2 = new LinkedHashMap();
                this.b.getValue();
                long jF2 = ((androidx.constraintlayout.compose.j) this.c).f(j, m.getLayoutDirection(), (androidx.constraintlayout.compose.i) this.d, list, linkedHashMap2);
                this.e.getValue();
                return m.n0((int) (jF2 >> 32), (int) (jF2 & 4294967295L), V.c(), new j((androidx.constraintlayout.compose.j) this.c, list, linkedHashMap2, 1));
            case 2:
                LinkedHashMap linkedHashMap3 = new LinkedHashMap();
                this.b.getValue();
                long jF3 = ((androidx.constraintlayout.compose.j) this.c).f(j, m.getLayoutDirection(), (androidx.constraintlayout.compose.i) this.d, list, linkedHashMap3);
                this.e.getValue();
                return m.n0((int) (jF3 >> 32), (int) (jF3 & 4294967295L), V.c(), new j((androidx.constraintlayout.compose.j) this.c, list, linkedHashMap3, 2));
            case 3:
                LinkedHashMap linkedHashMap4 = new LinkedHashMap();
                this.b.getValue();
                long jF4 = ((androidx.constraintlayout.compose.j) this.c).f(j, m.getLayoutDirection(), (androidx.constraintlayout.compose.i) this.d, list, linkedHashMap4);
                this.e.getValue();
                return m.n0((int) (jF4 >> 32), (int) (jF4 & 4294967295L), V.c(), new j((androidx.constraintlayout.compose.j) this.c, list, linkedHashMap4, 3));
            default:
                int size = list.size();
                for (int i = 0; i < size; i++) {
                    J j2 = (J) list.get(i);
                    if (Intrinsics.b(AbstractC0897s.h(j2), "badge")) {
                        W wB = j2.B(androidx.compose.ui.unit.a.a(j, 0, 0, 0, 0, 11));
                        int size2 = list.size();
                        for (int i2 = 0; i2 < size2; i2++) {
                            J j3 = (J) list.get(i2);
                            if (Intrinsics.b(AbstractC0897s.h(j3), "anchor")) {
                                W wB2 = j3.B(j);
                                C0893n c0893n = AbstractC0882c.a;
                                int iD0 = wB2.d0(c0893n);
                                C0893n c0893n2 = AbstractC0882c.b;
                                return m.n0(wB2.a, wB2.b, V.f(new Pair(c0893n, Integer.valueOf(iD0)), new Pair(c0893n2, Integer.valueOf(wB2.d0(c0893n2)))), new G(wB, m, wB2, (F0) this.b, (F0) this.e, (F0) this.c, (F0) this.d));
                            }
                        }
                        throw new NoSuchElementException("Collection contains no element matching the predicate.");
                    }
                }
                throw new NoSuchElementException("Collection contains no element matching the predicate.");
        }
    }

    public k(F0 f0, F0 f02, F0 f03, F0 f04) {
        this.a = 4;
        this.b = f0;
        this.e = f02;
        this.c = f03;
        this.d = f04;
    }
}
