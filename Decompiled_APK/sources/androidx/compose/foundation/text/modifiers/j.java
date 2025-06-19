package androidx.compose.foundation.text.modifiers;

import androidx.compose.ui.layout.r;
import androidx.compose.ui.node.a0;
import androidx.compose.ui.text.H;

/* loaded from: classes.dex */
public final class j {
    public static final j c = new j(null, null);
    public final r a;
    public final H b;

    public j(r rVar, H h) {
        this.a = rVar;
        this.b = h;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v2, types: [androidx.compose.ui.layout.r] */
    public static j a(j jVar, a0 a0Var, H h, int i) {
        a0 a0Var2 = a0Var;
        if ((i & 1) != 0) {
            a0Var2 = jVar.a;
        }
        if ((i & 2) != 0) {
            h = jVar.b;
        }
        return new j(a0Var2, h);
    }
}
