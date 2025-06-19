package androidx.compose.material.navigation;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.navigation.C1291m;
import androidx.navigation.C1295q;
import java.util.Iterator;
import java.util.Set;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class d extends r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ i b;
    public final /* synthetic */ InterfaceC0773a0 c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d(i iVar, InterfaceC0773a0 interfaceC0773a0, int i) {
        super(1);
        this.a = i;
        this.b = iVar;
        this.c = interfaceC0773a0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                Set set = (Set) this.c.getValue();
                C1295q c1295qB = this.b.b();
                Iterator it2 = set.iterator();
                while (it2.hasNext()) {
                    c1295qB.c((C1291m) it2.next());
                }
                break;
            default:
                C1291m c1291m = (C1291m) obj;
                boolean zContains = ((Set) this.c.getValue()).contains(c1291m);
                i iVar = this.b;
                if (zContains) {
                    iVar.b().c(c1291m);
                } else {
                    iVar.b().d(c1291m, false);
                }
                break;
        }
        return Unit.a;
    }
}
