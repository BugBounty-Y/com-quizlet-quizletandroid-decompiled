package androidx.compose.ui.layout;

import androidx.compose.runtime.C0775b0;
import java.util.Map;
import java.util.Set;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class C implements L {
    public final /* synthetic */ int a;
    public final /* synthetic */ L b;
    public final /* synthetic */ G c;
    public final /* synthetic */ int d;
    public final /* synthetic */ L e;

    public /* synthetic */ C(L l, G g, int i, L l2, int i2) {
        this.a = i2;
        this.c = g;
        this.d = i;
        this.e = l2;
        this.b = l;
    }

    @Override // androidx.compose.ui.layout.L
    public final int b() {
        switch (this.a) {
        }
        return this.b.b();
    }

    @Override // androidx.compose.ui.layout.L
    public final Map c() {
        switch (this.a) {
        }
        return this.b.c();
    }

    @Override // androidx.compose.ui.layout.L
    public final void d() {
        switch (this.a) {
            case 0:
                G g = this.c;
                g.e = this.d;
                this.e.d();
                Set setEntrySet = g.l.entrySet();
                C0775b0 predicate = new C0775b0(g, 16);
                Intrinsics.checkNotNullParameter(setEntrySet, "<this>");
                Intrinsics.checkNotNullParameter(predicate, "predicate");
                kotlin.collections.G.x(setEntrySet, predicate, true);
                break;
            default:
                G g2 = this.c;
                g2.d = this.d;
                this.e.d();
                g2.c(g2.d);
                break;
        }
    }

    @Override // androidx.compose.ui.layout.L
    public final Function1 e() {
        switch (this.a) {
        }
        return this.b.e();
    }

    @Override // androidx.compose.ui.layout.L
    public final int getWidth() {
        switch (this.a) {
        }
        return this.b.getWidth();
    }
}
