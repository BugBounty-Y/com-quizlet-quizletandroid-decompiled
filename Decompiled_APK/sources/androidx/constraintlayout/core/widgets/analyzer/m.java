package androidx.constraintlayout.core.widgets.analyzer;

import java.util.ArrayList;

/* loaded from: classes.dex */
public final class m {
    public p a;
    public ArrayList b;

    public static long a(g gVar, long j) {
        p pVar = gVar.d;
        if (pVar instanceof k) {
            return j;
        }
        ArrayList arrayList = gVar.k;
        int size = arrayList.size();
        long jMin = j;
        for (int i = 0; i < size; i++) {
            e eVar = (e) arrayList.get(i);
            if (eVar instanceof g) {
                g gVar2 = (g) eVar;
                if (gVar2.d != pVar) {
                    jMin = Math.min(jMin, a(gVar2, gVar2.f + j));
                }
            }
        }
        if (gVar != pVar.i) {
            return jMin;
        }
        long j2 = pVar.j();
        long j3 = j - j2;
        return Math.min(Math.min(jMin, a(pVar.h, j3)), j3 - r9.f);
    }

    public static long b(g gVar, long j) {
        p pVar = gVar.d;
        if (pVar instanceof k) {
            return j;
        }
        ArrayList arrayList = gVar.k;
        int size = arrayList.size();
        long jMax = j;
        for (int i = 0; i < size; i++) {
            e eVar = (e) arrayList.get(i);
            if (eVar instanceof g) {
                g gVar2 = (g) eVar;
                if (gVar2.d != pVar) {
                    jMax = Math.max(jMax, b(gVar2, gVar2.f + j));
                }
            }
        }
        if (gVar != pVar.h) {
            return jMax;
        }
        long j2 = pVar.j();
        long j3 = j + j2;
        return Math.max(Math.max(jMax, b(pVar.i, j3)), j3 - r9.f);
    }
}
