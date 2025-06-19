package com.quizlet.learn.viewmodel;

import androidx.lifecycle.p0;
import com.quizlet.learn.data.C4537b;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ G a;
    public final /* synthetic */ List b;
    public final /* synthetic */ List c;
    public final /* synthetic */ boolean d;

    public p(G g, List list, List list2, boolean z) {
        this.a = g;
        this.b = list;
        this.c = list2;
        this.d = z;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        C4537b it2 = (C4537b) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        G g = this.a;
        kotlinx.coroutines.E.A(p0.j(g), g.C1, null, new o(g, it2, this.b, this.c, this.d, null), 2);
    }
}
