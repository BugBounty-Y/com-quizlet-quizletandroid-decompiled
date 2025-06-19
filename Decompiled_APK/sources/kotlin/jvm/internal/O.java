package kotlin.jvm.internal;

import androidx.collection.Y;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import kotlin.InterfaceC4938g;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public abstract class O {
    public static Collection a(Object obj) {
        if ((obj instanceof kotlin.jvm.internal.markers.a) && !(obj instanceof kotlin.jvm.internal.markers.b)) {
            g(obj, "kotlin.collections.MutableCollection");
            throw null;
        }
        try {
            return (Collection) obj;
        } catch (ClassCastException e) {
            Intrinsics.j(e, O.class.getName());
            throw e;
        }
    }

    public static List b(Object obj) {
        if ((obj instanceof kotlin.jvm.internal.markers.a) && !(obj instanceof kotlin.jvm.internal.markers.c)) {
            g(obj, "kotlin.collections.MutableList");
            throw null;
        }
        try {
            return (List) obj;
        } catch (ClassCastException e) {
            Intrinsics.j(e, O.class.getName());
            throw e;
        }
    }

    public static Map c(Object obj) {
        if ((obj instanceof kotlin.jvm.internal.markers.a) && !(obj instanceof kotlin.jvm.internal.markers.e)) {
            g(obj, "kotlin.collections.MutableMap");
            throw null;
        }
        try {
            return (Map) obj;
        } catch (ClassCastException e) {
            Intrinsics.j(e, O.class.getName());
            throw e;
        }
    }

    public static void d(int i, Object obj) {
        if (obj == null || e(i, obj)) {
            return;
        }
        g(obj, "kotlin.jvm.functions.Function" + i);
        throw null;
    }

    public static boolean e(int i, Object obj) {
        int arity;
        if (obj instanceof InterfaceC4938g) {
            if (obj instanceof InterfaceC4954m) {
                arity = ((InterfaceC4954m) obj).getArity();
            } else if (obj instanceof Function0) {
                arity = 0;
            } else if (obj instanceof Function1) {
                arity = 1;
            } else if (obj instanceof Function2) {
                arity = 2;
            } else if (obj instanceof kotlin.jvm.functions.c) {
                arity = 3;
            } else if (obj instanceof kotlin.jvm.functions.d) {
                arity = 4;
            } else if (obj instanceof kotlin.jvm.functions.e) {
                arity = 5;
            } else if (obj instanceof kotlin.jvm.functions.f) {
                arity = 6;
            } else {
                boolean z = obj instanceof androidx.compose.runtime.internal.b;
                arity = z ? 7 : z ? 8 : z ? 9 : z ? 10 : z ? 11 : z ? 13 : z ? 14 : z ? 15 : z ? 16 : z ? 17 : z ? 18 : z ? 19 : z ? 20 : z ? 21 : -1;
            }
            if (arity == i) {
                return true;
            }
        }
        return false;
    }

    public static final Y f(Object[] array) {
        Intrinsics.checkNotNullParameter(array, "array");
        return new Y(array);
    }

    public static void g(Object obj, String str) {
        ClassCastException classCastException = new ClassCastException(android.support.v4.media.session.a.l(obj == null ? "null" : obj.getClass().getName(), " cannot be cast to ", str));
        Intrinsics.j(classCastException, O.class.getName());
        throw classCastException;
    }
}
