package com.squareup.moshi;

import java.io.Closeable;
import java.io.Flushable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* loaded from: classes3.dex */
public abstract class w implements Closeable, Flushable {
    public int a;
    public int[] b;
    public String[] c;
    public int[] d;
    public boolean e;
    public boolean f;
    public int g;

    public abstract s B(Number number);

    public abstract s C(String str);

    public abstract s D(boolean z);

    public abstract s a();

    public abstract s d();

    public abstract s f();

    public final String i() {
        return H.c(this.a, this.b, this.c, this.d);
    }

    public final void j(Object obj) {
        if (obj instanceof Map) {
            d();
            for (Map.Entry entry : ((Map) obj).entrySet()) {
                Object key = entry.getKey();
                if (!(key instanceof String)) {
                    throw new IllegalArgumentException(key == null ? "Map keys must be non-null" : "Map keys must be of type String: ".concat(key.getClass().getName()));
                }
                l((String) key);
                j(entry.getValue());
            }
            f();
            return;
        }
        if (obj instanceof List) {
            a();
            Iterator it2 = ((List) obj).iterator();
            while (it2.hasNext()) {
                j(it2.next());
            }
            ((s) this).Q(1, ']', 2);
            return;
        }
        if (obj instanceof String) {
            C((String) obj);
            return;
        }
        if (obj instanceof Boolean) {
            D(((Boolean) obj).booleanValue());
            return;
        }
        if (obj instanceof Double) {
            r(((Double) obj).doubleValue());
            return;
        }
        if (obj instanceof Long) {
            y(((Long) obj).longValue());
        } else if (obj instanceof Number) {
            B((Number) obj);
        } else {
            if (obj != null) {
                throw new IllegalArgumentException("Unsupported type: ".concat(obj.getClass().getName()));
            }
            p();
        }
    }

    public abstract s l(String str);

    public abstract s p();

    public final int q() {
        int i = this.a;
        if (i != 0) {
            return this.b[i - 1];
        }
        throw new IllegalStateException("JsonWriter is closed.");
    }

    public abstract s r(double d);

    public abstract s y(long j);
}
