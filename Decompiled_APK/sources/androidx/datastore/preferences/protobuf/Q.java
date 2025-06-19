package androidx.datastore.preferences.protobuf;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.concurrent.ConcurrentHashMap;

/* loaded from: classes.dex */
public final class Q {
    public static final Q c = new Q();
    public final ConcurrentHashMap b = new ConcurrentHashMap();
    public final C a = new C();

    public final U a(Class cls) {
        U uX;
        Class cls2;
        AbstractC1115w.a(cls, "messageType");
        ConcurrentHashMap concurrentHashMap = this.b;
        U u = (U) concurrentHashMap.get(cls);
        if (u != null) {
            return u;
        }
        C c2 = this.a;
        c2.getClass();
        Class cls3 = V.a;
        if (!AbstractC1113u.class.isAssignableFrom(cls) && (cls2 = V.a) != null && !cls2.isAssignableFrom(cls)) {
            throw new IllegalArgumentException("Message classes must extend GeneratedMessage or GeneratedMessageLite");
        }
        T tA = ((B) c2.a).a(cls);
        if ((tA.d & 2) == 2) {
            boolean zIsAssignableFrom = AbstractC1113u.class.isAssignableFrom(cls);
            AbstractC1113u abstractC1113u = tA.a;
            if (zIsAssignableFrom) {
                uX = new L(V.c, AbstractC1108o.a, abstractC1113u);
            } else {
                Z z = V.b;
                C1107n c1107n = AbstractC1108o.b;
                if (c1107n == null) {
                    throw new IllegalStateException("Protobuf runtime is not correctly loaded.");
                }
                uX = new L(z, c1107n, abstractC1113u);
            }
        } else if (AbstractC1113u.class.isAssignableFrom(cls)) {
            C1107n c1107n2 = null;
            M m = N.b;
            C1118z c1118z = A.b;
            b0 b0Var = V.c;
            if (AbstractC0147y.k(tA.a()) != 1) {
                c1107n2 = AbstractC1108o.a;
            }
            C1107n c1107n3 = c1107n2;
            G g = H.b;
            int[] iArr = K.n;
            if (!(tA instanceof T)) {
                tA.getClass();
                throw new ClassCastException();
            }
            uX = K.x(tA, m, c1118z, b0Var, c1107n3, g);
        } else {
            C1107n c1107n4 = null;
            M m2 = N.a;
            C1118z c1118z2 = A.a;
            Z z2 = V.b;
            if (AbstractC0147y.k(tA.a()) != 1 && (c1107n4 = AbstractC1108o.b) == null) {
                throw new IllegalStateException("Protobuf runtime is not correctly loaded.");
            }
            C1107n c1107n5 = c1107n4;
            G g2 = H.a;
            int[] iArr2 = K.n;
            if (!(tA instanceof T)) {
                tA.getClass();
                throw new ClassCastException();
            }
            uX = K.x(tA, m2, c1118z2, z2, c1107n5, g2);
        }
        U u2 = (U) concurrentHashMap.putIfAbsent(cls, uX);
        return u2 != null ? u2 : uX;
    }
}
