package io.ktor.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class n implements l {
    public final Map c;

    public n(Map values) {
        Intrinsics.checkNotNullParameter(values, "values");
        c cVar = new c();
        for (Map.Entry entry : values.entrySet()) {
            String str = (String) entry.getKey();
            List list = (List) entry.getValue();
            int size = list.size();
            ArrayList arrayList = new ArrayList(size);
            for (int i = 0; i < size; i++) {
                arrayList.add((String) list.get(i));
            }
            cVar.put(str, arrayList);
        }
        this.c = cVar;
    }

    @Override // io.ktor.util.l
    public final Set a() {
        Set setEntrySet = this.c.entrySet();
        Intrinsics.checkNotNullParameter(setEntrySet, "<this>");
        Set setUnmodifiableSet = Collections.unmodifiableSet(setEntrySet);
        Intrinsics.checkNotNullExpressionValue(setUnmodifiableSet, "unmodifiableSet(...)");
        return setUnmodifiableSet;
    }

    @Override // io.ktor.util.l
    public final void b(Function2 body) {
        Intrinsics.checkNotNullParameter(body, "body");
        for (Map.Entry entry : this.c.entrySet()) {
            body.invoke((String) entry.getKey(), (List) entry.getValue());
        }
    }

    @Override // io.ktor.util.l
    public final boolean c() {
        return true;
    }

    @Override // io.ktor.util.l
    public final String d(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        List list = (List) this.c.get(name);
        if (list != null) {
            return (String) CollectionsKt.firstOrNull(list);
        }
        return null;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof l)) {
            return false;
        }
        l lVar = (l) obj;
        if (true != lVar.c()) {
            return false;
        }
        return Intrinsics.b(a(), lVar.a());
    }

    public final int hashCode() {
        Set setA = a();
        return setA.hashCode() + (Boolean.hashCode(true) * 961);
    }

    @Override // io.ktor.util.l
    public final boolean isEmpty() {
        return this.c.isEmpty();
    }
}
