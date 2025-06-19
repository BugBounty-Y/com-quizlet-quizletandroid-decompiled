package androidx.compose.ui.scrollcapture;

import androidx.compose.ui.node.a0;
import androidx.compose.ui.semantics.o;

/* loaded from: classes.dex */
public final class m {
    public final o a;
    public final int b;
    public final androidx.compose.ui.unit.i c;
    public final a0 d;

    public m(o oVar, int i, androidx.compose.ui.unit.i iVar, a0 a0Var) {
        this.a = oVar;
        this.b = i;
        this.c = iVar;
        this.d = a0Var;
    }

    public final String toString() {
        return "ScrollCaptureCandidate(node=" + this.a + ", depth=" + this.b + ", viewportBoundsInWindow=" + this.c + ", coordinates=" + this.d + ')';
    }
}
