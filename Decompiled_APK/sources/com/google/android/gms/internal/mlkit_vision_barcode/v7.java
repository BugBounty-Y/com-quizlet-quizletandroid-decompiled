package com.google.android.gms.internal.mlkit_vision_barcode;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3332e;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.Pair;

/* loaded from: classes2.dex */
public abstract class v7 {
    public static final /* synthetic */ int a = 0;

    /* JADX WARN: Removed duplicated region for block: B:23:0x0060  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(androidx.glance.appwidget.B0 r5) {
        /*
            java.util.ArrayList r0 = r5.c
            boolean r0 = r0.isEmpty()
            java.util.ArrayList r1 = r5.c
            r2 = 1
            if (r0 != 0) goto L59
            if (r1 == 0) goto L14
            boolean r0 = r1.isEmpty()
            if (r0 == 0) goto L14
            goto L29
        L14:
            java.util.Iterator r0 = r1.iterator()
        L18:
            boolean r3 = r0.hasNext()
            if (r3 == 0) goto L29
            java.lang.Object r3 = r0.next()
            androidx.glance.k r3 = (androidx.glance.k) r3
            boolean r3 = r3 instanceof androidx.glance.appwidget.E
            if (r3 != 0) goto L18
            goto L59
        L29:
            java.util.Iterator r0 = r1.iterator()
        L2d:
            boolean r1 = r0.hasNext()
            if (r1 == 0) goto L70
            java.lang.Object r1 = r0.next()
            androidx.glance.k r1 = (androidx.glance.k) r1
            java.lang.String r3 = "null cannot be cast to non-null type androidx.glance.appwidget.EmittableSizeBox"
            kotlin.jvm.internal.Intrinsics.e(r1, r3)
            androidx.glance.appwidget.E r1 = (androidx.glance.appwidget.E) r1
            java.util.ArrayList r1 = r1.c
            int r3 = r1.size()
            if (r3 == r2) goto L2d
            androidx.glance.layout.i r3 = new androidx.glance.layout.i
            r3.<init>()
            java.util.ArrayList r4 = r3.c
            kotlin.collections.G.u(r4, r1)
            r1.clear()
            r1.add(r3)
            goto L2d
        L59:
            int r0 = r1.size()
            if (r0 != r2) goto L60
            goto L70
        L60:
            androidx.glance.layout.i r0 = new androidx.glance.layout.i
            r0.<init>()
            java.util.ArrayList r2 = r0.c
            kotlin.collections.G.u(r2, r1)
            r1.clear()
            r1.add(r0)
        L70:
            b(r5)
            c(r5)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.v7.a(androidx.glance.appwidget.B0):void");
    }

    public static final void b(androidx.glance.m mVar) {
        Iterator it2 = mVar.c.iterator();
        while (it2.hasNext()) {
            androidx.glance.k kVar = (androidx.glance.k) it2.next();
            if (kVar instanceof androidx.glance.m) {
                b((androidx.glance.m) kVar);
            }
        }
        androidx.glance.layout.m mVar2 = (androidx.glance.layout.m) mVar.a().a(null, androidx.glance.appwidget.q0.q);
        androidx.glance.unit.g gVar = androidx.glance.unit.f.a;
        boolean z = (mVar2 != null ? mVar2.a : gVar) instanceof androidx.glance.unit.f;
        ArrayList arrayList = mVar.c;
        if (z && (arrayList == null || !arrayList.isEmpty())) {
            Iterator it3 = arrayList.iterator();
            while (true) {
                if (!it3.hasNext()) {
                    break;
                }
                androidx.glance.layout.m mVar3 = (androidx.glance.layout.m) ((androidx.glance.k) it3.next()).a().a(null, androidx.glance.appwidget.q0.s);
                if ((mVar3 != null ? mVar3.a : null) instanceof androidx.glance.unit.e) {
                    mVar.b(AbstractC3332e.c(mVar.a()));
                    break;
                }
            }
        }
        androidx.glance.layout.t tVar = (androidx.glance.layout.t) mVar.a().a(null, androidx.glance.appwidget.q0.r);
        if (tVar != null) {
            gVar = tVar.a;
        }
        if (gVar instanceof androidx.glance.unit.f) {
            if (arrayList == null || !arrayList.isEmpty()) {
                Iterator it4 = arrayList.iterator();
                while (it4.hasNext()) {
                    androidx.glance.layout.t tVar2 = (androidx.glance.layout.t) ((androidx.glance.k) it4.next()).a().a(null, androidx.glance.appwidget.q0.t);
                    if ((tVar2 != null ? tVar2.a : null) instanceof androidx.glance.unit.e) {
                        mVar.b(AbstractC3332e.e(mVar.a()));
                        return;
                    }
                }
            }
        }
    }

    public static final void c(androidx.glance.m mVar) {
        androidx.glance.appwidget.x0 x0Var = androidx.glance.appwidget.x0.d;
        Iterator it2 = mVar.c.iterator();
        int i = 0;
        while (it2.hasNext()) {
            Object next = it2.next();
            int i2 = i + 1;
            if (i < 0) {
                kotlin.collections.B.p();
                throw null;
            }
            androidx.glance.k kVar = (androidx.glance.k) x0Var.invoke((androidx.glance.k) next);
            mVar.c.set(i, kVar);
            if (kVar instanceof androidx.glance.m) {
                c((androidx.glance.m) kVar);
            }
            i = i2;
        }
    }

    public static final LinkedHashMap d(androidx.glance.m mVar) {
        ArrayList arrayList = mVar.c;
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        Iterator it2 = arrayList.iterator();
        int i = 0;
        while (it2.hasNext()) {
            Object next = it2.next();
            int i2 = i + 1;
            if (i < 0) {
                kotlin.collections.B.p();
                throw null;
            }
            androidx.glance.k kVar = (androidx.glance.k) next;
            androidx.glance.p pVarA = kVar.a();
            Pair pair = pVarA.c(androidx.glance.appwidget.x0.b) ? (Pair) pVarA.a(new Pair(null, androidx.glance.n.a), androidx.glance.appwidget.q0.o) : new Pair(null, pVarA);
            androidx.glance.action.b bVar = (androidx.glance.action.b) pair.a;
            androidx.glance.p pVar = (androidx.glance.p) pair.b;
            androidx.glance.action.a aVar = bVar != null ? bVar.a : null;
            Pair pair2 = aVar instanceof androidx.glance.action.e ? new Pair(aVar, pVar) : new Pair(null, pVar);
            if (kVar instanceof androidx.glance.m) {
                for (Map.Entry entry : d((androidx.glance.m) kVar).entrySet()) {
                    String str = (String) entry.getKey();
                    List list = (List) entry.getValue();
                    Object arrayList2 = linkedHashMap.get(str);
                    if (arrayList2 == null) {
                        arrayList2 = new ArrayList();
                        linkedHashMap.put(str, arrayList2);
                    }
                    ((List) arrayList2).addAll(list);
                }
            }
            i = i2;
        }
        return linkedHashMap;
    }
}
