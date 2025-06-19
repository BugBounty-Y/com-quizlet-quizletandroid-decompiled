package io.ktor.http;

import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.C;

/* loaded from: classes3.dex */
public final class g {
    public final String a;
    public final List b;

    public g(String value, List params) {
        Object next;
        String str;
        Intrinsics.checkNotNullParameter(value, "value");
        Intrinsics.checkNotNullParameter(params, "params");
        this.a = value;
        this.b = params;
        Iterator it2 = params.iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            } else {
                next = it2.next();
                if (Intrinsics.b(((h) next).a, "q")) {
                    break;
                }
            }
        }
        h hVar = (h) next;
        if (hVar == null || (str = hVar.b) == null) {
            return;
        }
        C.e(str);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return Intrinsics.b(this.a, gVar.a) && Intrinsics.b(this.b, gVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "HeaderValue(value=" + this.a + ", params=" + this.b + ')';
    }
}
