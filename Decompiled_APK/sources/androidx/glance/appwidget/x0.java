package androidx.glance.appwidget;

import android.util.Log;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3332e;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Pair;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class x0 extends kotlin.jvm.internal.r implements Function1 {
    public static final x0 b = new x0(1, 0);
    public static final x0 c = new x0(1, 1);
    public static final x0 d = new x0(1, 2);
    public static final x0 e = new x0(1, 3);
    public static final x0 f = new x0(1, 4);
    public static final x0 g = new x0(1, 5);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ x0(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.glance.l lVar;
        androidx.glance.l lVar2;
        androidx.glance.p pVarD;
        androidx.glance.p pVarD2;
        switch (this.a) {
            case 0:
                return Boolean.valueOf(((androidx.glance.o) obj) instanceof androidx.glance.action.b);
            case 1:
                androidx.glance.o oVar = (androidx.glance.o) obj;
                return Boolean.valueOf((oVar instanceof androidx.glance.layout.t) || (oVar instanceof androidx.glance.layout.m) || (oVar instanceof A));
            case 2:
                androidx.glance.k kVar = (androidx.glance.k) obj;
                boolean z = kVar instanceof androidx.glance.appwidget.lazy.b;
                if (z) {
                    androidx.glance.appwidget.lazy.b bVar = (androidx.glance.appwidget.lazy.b) kVar;
                    androidx.glance.layout.i iVar = new androidx.glance.layout.i();
                    kotlin.collections.G.u(iVar.c, bVar.c);
                    iVar.e = bVar.d;
                    iVar.d = bVar.e;
                    ArrayList arrayList = bVar.c;
                    arrayList.clear();
                    arrayList.add(iVar);
                    bVar.d = androidx.glance.layout.c.e;
                }
                if (z || (kVar instanceof E) || !kVar.a().c(new x0(1, 6))) {
                    return kVar;
                }
                ArrayList arrayList2 = new ArrayList();
                ArrayList arrayList3 = new ArrayList();
                androidx.glance.p pVarA = kVar.a();
                boolean zC = pVarA.c(e);
                androidx.glance.p pVar = androidx.glance.n.a;
                Pair pair = zC ? (Pair) pVarA.a(new Pair(null, pVar), q0.u) : new Pair(null, pVarA);
                androidx.glance.e eVar = (androidx.glance.e) pair.a;
                androidx.glance.p pVar2 = (androidx.glance.p) pair.b;
                if (eVar == null) {
                    lVar = null;
                } else if (eVar instanceof androidx.glance.d) {
                    lVar = new androidx.glance.l();
                    lVar.a = AbstractC3332e.d(pVar);
                    lVar.b = ((androidx.glance.d) eVar).a;
                    lVar.d = 2;
                    lVar.c = null;
                } else {
                    if (eVar instanceof androidx.glance.c) {
                        arrayList3.add(eVar);
                    }
                    lVar = null;
                }
                if (((Number) pVar2.a(0, q0.w)).intValue() > 1) {
                    Log.w("GlanceAppWidget", "More than one clickable defined on the same GlanceModifier, only the last one will be used.");
                }
                Pair pair2 = pVar2.c(f) ? (Pair) pVar2.a(new Pair(null, pVar), q0.v) : new Pair(null, pVar2);
                androidx.glance.action.b bVar2 = (androidx.glance.action.b) pair2.a;
                androidx.glance.p pVar3 = (androidx.glance.p) pair2.b;
                arrayList2.add(bVar2);
                if (bVar2 != null) {
                    androidx.glance.a aVar = new androidx.glance.a(R.drawable.glance_ripple);
                    lVar2 = new androidx.glance.l();
                    lVar2.a = AbstractC3332e.d(pVar);
                    lVar2.b = aVar;
                } else {
                    lVar2 = null;
                }
                G g2 = pVar3.c(c) ? (G) pVar3.a(new G((androidx.glance.p) null, 3), q0.p) : new G(pVar3, 1);
                arrayList2.add(g2.a);
                arrayList3.add(AbstractC3332e.d(g2.b));
                androidx.glance.layout.i iVar2 = new androidx.glance.layout.i();
                Iterator it2 = arrayList2.iterator();
                androidx.glance.p pVar4 = pVar;
                while (it2.hasNext()) {
                    androidx.glance.p pVar5 = (androidx.glance.p) it2.next();
                    if (pVar5 != null && (pVarD2 = pVar4.d(pVar5)) != null) {
                        pVar4 = pVarD2;
                    }
                }
                iVar2.d = pVar4;
                Iterator it3 = arrayList3.iterator();
                while (it3.hasNext()) {
                    androidx.glance.p pVar6 = (androidx.glance.p) it3.next();
                    if (pVar6 != null && (pVarD = pVar.d(pVar6)) != null) {
                        pVar = pVarD;
                    }
                }
                kVar.b(pVar);
                ArrayList arrayList4 = iVar2.c;
                if (lVar != null) {
                    arrayList4.add(lVar);
                }
                arrayList4.add(kVar);
                if (lVar2 != null) {
                    arrayList4.add(lVar2);
                }
                return iVar2;
            case 3:
                return Boolean.valueOf(((androidx.glance.o) obj) instanceof androidx.glance.e);
            case 4:
                return Boolean.valueOf(((androidx.glance.o) obj) instanceof androidx.glance.action.b);
            case 5:
                return Boolean.FALSE;
            default:
                androidx.glance.o oVar2 = (androidx.glance.o) obj;
                return Boolean.valueOf((oVar2 instanceof androidx.glance.d) || (oVar2 instanceof androidx.glance.action.b));
        }
    }
}
