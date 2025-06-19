package androidx.compose.ui.viewinterop;

import androidx.compose.ui.node.E;
import androidx.compose.ui.node.g0;
import androidx.compose.ui.platform.C0954m;
import androidx.compose.ui.platform.C0971v;
import androidx.core.view.V;
import java.util.HashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class c extends r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ p b;
    public final /* synthetic */ E c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c(p pVar, E e, int i) {
        super(1);
        this.a = i;
        this.b = pVar;
        this.c = e;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                g0 g0Var = (g0) obj;
                C0971v c0971v = g0Var instanceof C0971v ? (C0971v) g0Var : null;
                p pVar = this.b;
                if (c0971v != null) {
                    HashMap<i, E> holderToLayoutNode = c0971v.getAndroidViewsHandler$ui_release().getHolderToLayoutNode();
                    E e = this.c;
                    holderToLayoutNode.put(pVar, e);
                    c0971v.getAndroidViewsHandler$ui_release().addView(pVar);
                    c0971v.getAndroidViewsHandler$ui_release().getLayoutNodeToHolder().put(e, pVar);
                    pVar.setImportantForAccessibility(1);
                    V.o(pVar, new C0954m(c0971v, e, c0971v));
                }
                if (pVar.getView().getParent() != pVar) {
                    pVar.addView(pVar.getView());
                }
                break;
            case 1:
                k.h(this.b, this.c);
                break;
            default:
                p pVar2 = this.b;
                k.h(pVar2, this.c);
                ((C0971v) pVar2.c).u = true;
                break;
        }
        return Unit.a;
    }
}
