package androidx.compose.ui.layout;

import androidx.compose.ui.node.C0922s;
import androidx.compose.ui.node.C0923t;
import java.util.Map;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class A implements L {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Map c;
    public final /* synthetic */ B d;
    public final /* synthetic */ G e;
    public final /* synthetic */ Function1 f;

    public A(int i, int i2, Map map, B b, G g, Function1 function1) {
        this.a = i;
        this.b = i2;
        this.c = map;
        this.d = b;
        this.e = g;
        this.f = function1;
    }

    @Override // androidx.compose.ui.layout.L
    public final int b() {
        return this.b;
    }

    @Override // androidx.compose.ui.layout.L
    public final Map c() {
        return this.c;
    }

    @Override // androidx.compose.ui.layout.L
    public final void d() {
        C0922s c0922s;
        boolean zA0 = this.d.a0();
        Function1 function1 = this.f;
        G g = this.e;
        if (!zA0 || (c0922s = ((C0923t) g.a.w.c).L) == null) {
            function1.invoke(((C0923t) g.a.w.c).i);
        } else {
            function1.invoke(c0922s.i);
        }
    }

    @Override // androidx.compose.ui.layout.L
    public final Function1 e() {
        return null;
    }

    @Override // androidx.compose.ui.layout.L
    public final int getWidth() {
        return this.a;
    }
}
