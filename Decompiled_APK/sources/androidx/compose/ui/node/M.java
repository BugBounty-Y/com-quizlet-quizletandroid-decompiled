package androidx.compose.ui.node;

import java.util.Map;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class M implements androidx.compose.ui.layout.L {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Map c;
    public final /* synthetic */ Function1 d;
    public final /* synthetic */ O e;

    public M(int i, int i2, Map map, Function1 function1, O o) {
        this.a = i;
        this.b = i2;
        this.c = map;
        this.d = function1;
        this.e = o;
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
        this.d.invoke(this.e.i);
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
