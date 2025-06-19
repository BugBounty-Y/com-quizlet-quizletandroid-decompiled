package com.quizlet.assembly.widgets.progress;

import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d {
    public final List a;

    public d(List progresses) {
        Intrinsics.checkNotNullParameter(progresses, "progresses");
        this.a = progresses;
    }

    public final int a() {
        List list = this.a;
        if (list.isEmpty() || b() == 0) {
            return 0;
        }
        return (((c) list.get(0)).b * 100) / b();
    }

    public final int b() {
        Iterator it2 = this.a.iterator();
        int i = 0;
        while (it2.hasNext()) {
            i += ((c) it2.next()).b;
        }
        return i;
    }

    public final boolean c() {
        List list = this.a;
        return !list.isEmpty() && ((c) list.get(0)).b == b();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof d) && Intrinsics.b(this.a, ((d) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("ProgressViewState(progresses="), this.a);
    }
}
