package androidx.glance.appwidget.lazy;

import java.util.ArrayList;
import kotlin.Pair;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class h {
    public final /* synthetic */ ArrayList a;

    public h(ArrayList arrayList) {
        this.a = arrayList;
    }

    public final void a(long j, androidx.compose.runtime.internal.d dVar) {
        if (j != Long.MIN_VALUE && j <= -4611686018427387904L) {
            throw new IllegalArgumentException("You may not specify item ids less than -4611686018427387904 in a Glance\nwidget. These are reserved.");
        }
        this.a.add(new Pair(Long.valueOf(j), dVar));
    }

    public final void b(int i, Function1 function1, androidx.compose.runtime.internal.d dVar) {
        for (int i2 = 0; i2 < i; i2++) {
            a(((Number) function1.invoke(Integer.valueOf(i2))).longValue(), new androidx.compose.runtime.internal.d(true, 19676320, new g(dVar, i2)));
        }
    }
}
