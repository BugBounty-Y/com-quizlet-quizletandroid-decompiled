package kotlin.jvm.internal;

import java.util.Collections;
import java.util.List;
import kotlin.collections.C4933y;
import kotlin.reflect.KTypeProjection;

/* loaded from: classes3.dex */
public class K {
    public static final L a;

    static {
        L l = null;
        try {
            l = (L) Class.forName("kotlin.reflect.jvm.internal.ReflectionFactoryImpl").newInstance();
        } catch (ClassCastException | ClassNotFoundException | IllegalAccessException | InstantiationException unused) {
        }
        if (l == null) {
            l = new L();
        }
        a = l;
    }

    public static C4950i a(Class cls) {
        a.getClass();
        return new C4950i(cls);
    }

    public static void b(Q q, U u) {
        L l = a;
        List upperBounds = Collections.singletonList(u);
        l.getClass();
        Intrinsics.checkNotNullParameter(upperBounds, "upperBounds");
        if (q.b == null) {
            q.b = upperBounds;
            return;
        }
        throw new IllegalStateException(("Upper bounds of type parameter '" + q + "' have already been initialized.").toString());
    }

    public static U c(Class cls) {
        C4950i c4950iA = a(cls);
        List list = Collections.EMPTY_LIST;
        a.getClass();
        return L.b(c4950iA, list);
    }

    public static U d(Class cls, KTypeProjection... kTypeProjectionArr) {
        C4950i c4950iA = a(cls);
        List listP = C4933y.P(kTypeProjectionArr);
        a.getClass();
        return L.b(c4950iA, listP);
    }
}
