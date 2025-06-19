package retrofit2;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/* renamed from: retrofit2.p, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5191p {
    public final Class a;
    public final Object b;
    public final Method c;
    public final List d;

    public C5191p(Class cls, Object obj, Method method, ArrayList arrayList) {
        this.a = cls;
        this.b = obj;
        this.c = method;
        this.d = Collections.unmodifiableList(arrayList);
    }

    public final String toString() {
        return String.format("%s.%s() %s", this.a.getName(), this.c.getName(), this.d);
    }
}
