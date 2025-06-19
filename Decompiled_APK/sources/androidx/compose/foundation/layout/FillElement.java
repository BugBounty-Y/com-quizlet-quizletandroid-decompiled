package androidx.compose.foundation.layout;

import androidx.camera.camera2.internal.AbstractC0147y;
import kotlin.Metadata;

/* JADX INFO: Access modifiers changed from: package-private */
@Metadata
/* loaded from: classes.dex */
public final class FillElement extends androidx.compose.ui.node.T {
    public final int b;
    public final float c;

    public FillElement(float f, int i) {
        this.b = i;
        this.c = f;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FillElement)) {
            return false;
        }
        FillElement fillElement = (FillElement) obj;
        return this.b == fillElement.b && this.c == fillElement.c;
    }

    public final int hashCode() {
        return Float.hashCode(this.c) + (AbstractC0147y.k(this.b) * 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        P p = new P();
        p.n = this.b;
        p.o = this.c;
        return p;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        P p = (P) pVar;
        p.n = this.b;
        p.o = this.c;
    }
}
