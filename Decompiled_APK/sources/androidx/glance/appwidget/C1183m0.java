package androidx.glance.appwidget;

import androidx.glance.appwidget.protobuf.AbstractC1205q;
import java.util.Map;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.glance.appwidget.m0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1183m0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ C1185n0 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1183m0(C1185n0 c1185n0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c1185n0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1183m0 c1183m0 = new C1183m0(this.k, hVar);
        c1183m0.j = obj;
        return c1183m0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1183m0) create((androidx.glance.appwidget.proto.e) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        androidx.glance.appwidget.proto.e eVar = (androidx.glance.appwidget.proto.e) this.j;
        AbstractC1205q abstractC1205q = (AbstractC1205q) eVar.b(5);
        if (!abstractC1205q.a.equals(eVar)) {
            abstractC1205q.d();
            AbstractC1205q.e(abstractC1205q.b, eVar);
        }
        androidx.glance.appwidget.proto.d dVar = (androidx.glance.appwidget.proto.d) abstractC1205q;
        int iP = ((androidx.glance.appwidget.proto.e) dVar.b).p();
        dVar.d();
        androidx.glance.appwidget.proto.e.m((androidx.glance.appwidget.proto.e) dVar.b, iP);
        dVar.d();
        androidx.glance.appwidget.proto.e.l((androidx.glance.appwidget.proto.e) dVar.b);
        C1185n0 c1185n0 = this.k;
        for (Map.Entry entry : c1185n0.b.entrySet()) {
            androidx.glance.appwidget.proto.i iVar = (androidx.glance.appwidget.proto.i) entry.getKey();
            int iIntValue = ((Number) entry.getValue()).intValue();
            if (c1185n0.e.contains(new Integer(iIntValue))) {
                androidx.glance.appwidget.proto.f fVarO = androidx.glance.appwidget.proto.g.o();
                fVarO.d();
                androidx.glance.appwidget.proto.g.k((androidx.glance.appwidget.proto.g) fVarO.b, iVar);
                fVarO.d();
                androidx.glance.appwidget.proto.g.l((androidx.glance.appwidget.proto.g) fVarO.b, iIntValue);
                dVar.d();
                androidx.glance.appwidget.proto.e.k((androidx.glance.appwidget.proto.e) dVar.b, (androidx.glance.appwidget.proto.g) fVarO.b());
            }
        }
        return dVar.b();
    }
}
