package androidx.compose.foundation.text;

import androidx.compose.ui.text.input.C1008k;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.CollectionsKt;

/* loaded from: classes.dex */
public final class y0 {
    public final C0492h0 a;
    public final androidx.compose.foundation.text.selection.i0 b;
    public final androidx.compose.ui.text.input.A c;
    public final boolean d;
    public final boolean e;
    public final androidx.compose.foundation.text.selection.o0 f;
    public final androidx.compose.ui.text.input.s g;
    public final Q0 h;
    public final T i;
    public final C0478a0 j;
    public final D k;
    public final int l;

    public y0(C0492h0 c0492h0, androidx.compose.foundation.text.selection.i0 i0Var, androidx.compose.ui.text.input.A a, boolean z, boolean z2, androidx.compose.foundation.text.selection.o0 o0Var, androidx.compose.ui.text.input.s sVar, Q0 q0, T t, D d, int i) {
        C0478a0 c0478a0 = AbstractC0484d0.a;
        this.a = c0492h0;
        this.b = i0Var;
        this.c = a;
        this.d = z;
        this.e = z2;
        this.f = o0Var;
        this.g = sVar;
        this.h = q0;
        this.i = t;
        this.j = c0478a0;
        this.k = d;
        this.l = i;
    }

    public final void a(List list) {
        com.quizlet.data.repository.explanations.myexplanations.a aVar = this.a.d;
        ArrayList arrayListY0 = CollectionsKt.y0(list);
        arrayListY0.add(0, new C1008k());
        this.k.invoke(aVar.f(arrayListY0));
    }
}
