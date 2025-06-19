package androidx.navigation;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.Set;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.s0;

/* renamed from: androidx.navigation.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1294p implements Function0 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ C1295q b;
    public final /* synthetic */ C1291m c;

    public /* synthetic */ C1294p(C1295q c1295q, C1291m c1291m) {
        this.b = c1295q;
        this.c = c1291m;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                C1295q c1295q = this.b;
                c1295q.getClass();
                C1291m entry = this.c;
                Intrinsics.checkNotNullParameter(entry, "entry");
                s0 s0Var = c1295q.c;
                Set set = (Set) s0Var.getValue();
                Intrinsics.checkNotNullParameter(set, "<this>");
                LinkedHashSet linkedHashSet = new LinkedHashSet(kotlin.collections.U.a(set.size()));
                boolean z = false;
                for (Object obj : set) {
                    boolean z2 = true;
                    if (!z && Intrinsics.b(obj, entry)) {
                        z = true;
                        z2 = false;
                    }
                    if (z2) {
                        linkedHashSet.add(obj);
                    }
                }
                s0Var.m(null, linkedHashSet);
                return Unit.a;
            default:
                C1295q c1295q2 = this.b;
                C1291m popUpTo = this.c;
                Intrinsics.checkNotNullParameter(popUpTo, "popUpTo");
                synchronized (c1295q2.a) {
                    try {
                        s0 s0Var2 = c1295q2.b;
                        Iterable iterable = (Iterable) s0Var2.getValue();
                        ArrayList arrayList = new ArrayList();
                        for (Object obj2 : iterable) {
                            if (Intrinsics.b((C1291m) obj2, popUpTo)) {
                                s0Var2.getClass();
                                s0Var2.m(null, arrayList);
                            } else {
                                arrayList.add(obj2);
                            }
                        }
                        s0Var2.getClass();
                        s0Var2.m(null, arrayList);
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return Unit.a;
        }
    }

    public /* synthetic */ C1294p(C1295q c1295q, C1291m c1291m, boolean z) {
        this.b = c1295q;
        this.c = c1291m;
    }
}
