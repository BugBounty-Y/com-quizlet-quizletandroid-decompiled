package androidx.constraintlayout.compose;

import java.util.ArrayList;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class g {
    public final androidx.constraintlayout.core.parser.g a;
    public com.quizlet.data.repository.school.membership.a b;
    public int c;
    public final ArrayList d;

    public g() {
        new ArrayList();
        this.a = new androidx.constraintlayout.core.parser.g(new char[0]);
        this.c = 0;
        this.d = new ArrayList();
    }

    public final b a() {
        ArrayList arrayList = this.d;
        int i = this.c;
        this.c = i + 1;
        b bVar = (b) CollectionsKt.O(i, arrayList);
        if (bVar != null) {
            return bVar;
        }
        b bVar2 = new b(Integer.valueOf(this.c));
        arrayList.add(bVar2);
        return bVar2;
    }

    public final void b() {
        this.a.e.clear();
        this.c = 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        return Intrinsics.b(this.a, ((g) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }
}
