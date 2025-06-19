package com.quizlet.search.data;

import com.quizlet.data.model.B1;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h extends i {
    public final String a;
    public final List b;
    public final ArrayList c;

    public h(String userQuery, List suggestions) {
        Intrinsics.checkNotNullParameter(userQuery, "userQuery");
        Intrinsics.checkNotNullParameter(suggestions, "suggestions");
        this.a = userQuery;
        this.b = suggestions;
        ArrayList arrayList = new ArrayList(C.q(suggestions, 10));
        Iterator it2 = suggestions.iterator();
        while (it2.hasNext()) {
            arrayList.add(new com.quizlet.search.data.typeahead.a(this.a, ((B1) it2.next()).a));
        }
        this.c = arrayList;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return Intrinsics.b(this.a, hVar.a) && Intrinsics.b(this.b, hVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "MainState(userQuery=" + this.a + ", suggestions=" + this.b + ")";
    }
}
