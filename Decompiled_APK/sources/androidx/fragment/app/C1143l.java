package androidx.fragment.app;

import android.view.ViewGroup;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.fragment.app.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1143l extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ C1145m b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ ViewGroup d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1143l(C1145m c1145m, ViewGroup viewGroup, Object obj) {
        super(0);
        this.b = c1145m;
        this.d = viewGroup;
        this.c = obj;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.f.e(this.d, this.c);
                break;
            default:
                C1145m c1145m = this.b;
                ArrayList arrayList = c1145m.c;
                z0 z0Var = c1145m.f;
                if (arrayList.isEmpty()) {
                    AbstractC1136h0.N(2);
                    Object obj = c1145m.q;
                    Intrinsics.d(obj);
                    z0Var.d(obj, new RunnableC1141k(c1145m, this.d));
                } else {
                    Iterator it2 = arrayList.iterator();
                    while (it2.hasNext()) {
                        if (!((C1146n) it2.next()).a.g) {
                            AbstractC1136h0.N(2);
                            androidx.core.os.b bVar = new androidx.core.os.b();
                            z0Var.u(((C1146n) c1145m.c.get(0)).a.c, this.c, bVar, new RunnableC1152u(c1145m, 3));
                            bVar.a();
                        }
                    }
                    AbstractC1136h0.N(2);
                    Object obj2 = c1145m.q;
                    Intrinsics.d(obj2);
                    z0Var.d(obj2, new RunnableC1141k(c1145m, this.d));
                }
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1143l(C1145m c1145m, Object obj, ViewGroup viewGroup) {
        super(0);
        this.b = c1145m;
        this.c = obj;
        this.d = viewGroup;
    }
}
