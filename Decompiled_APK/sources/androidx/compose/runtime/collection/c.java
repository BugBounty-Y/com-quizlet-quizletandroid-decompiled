package androidx.compose.runtime.collection;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.List;

/* loaded from: classes.dex */
public abstract class c {
    public static final void a(int i, List list) {
        int size = list.size();
        if (i < 0 || i >= size) {
            c(i, size);
        }
    }

    public static final void b(int i, int i2, List list) {
        if (i > i2) {
            f(i, i2);
        }
        if (i < 0) {
            d(i);
        }
        if (i2 > list.size()) {
            e(i2, list.size());
        }
    }

    private static final void c(int i, int i2) {
        throw new IndexOutOfBoundsException(android.support.v4.media.session.a.j("Index ", i, " is out of bounds. The list has ", " elements.", i2));
    }

    private static final void d(int i) {
        throw new IndexOutOfBoundsException(AbstractC0147y.c(i, "fromIndex (", ") is less than 0."));
    }

    private static final void e(int i, int i2) {
        throw new IndexOutOfBoundsException("toIndex (" + i + ") is more than than the list size (" + i2 + ')');
    }

    private static final void f(int i, int i2) {
        throw new IllegalArgumentException(android.support.v4.media.session.a.j("Indices are out of order. fromIndex (", i, ") is greater than toIndex (", ").", i2));
    }
}
