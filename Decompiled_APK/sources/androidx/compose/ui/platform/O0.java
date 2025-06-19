package androidx.compose.ui.platform;

import androidx.collection.AbstractC0215m;
import androidx.collection.C0223v;
import androidx.collection.C0224w;
import java.util.List;

/* loaded from: classes.dex */
public final class O0 {
    public final androidx.compose.ui.semantics.k a;
    public final C0224w b;

    public O0(androidx.compose.ui.semantics.o oVar, C0223v c0223v) {
        this.a = oVar.d;
        int[] iArr = AbstractC0215m.a;
        this.b = new C0224w();
        List listH = androidx.compose.ui.semantics.o.h(oVar, 4);
        int size = listH.size();
        for (int i = 0; i < size; i++) {
            androidx.compose.ui.semantics.o oVar2 = (androidx.compose.ui.semantics.o) listH.get(i);
            if (c0223v.b(oVar2.g)) {
                this.b.a(oVar2.g);
            }
        }
    }
}
