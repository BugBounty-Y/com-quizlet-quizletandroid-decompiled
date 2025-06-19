package androidx.glance.appwidget.protobuf;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.concurrent.ConcurrentHashMap;

/* loaded from: classes.dex */
public final class L {
    public static final L c = new L();
    public final ConcurrentHashMap b = new ConcurrentHashMap();
    public final A a = new A();

    public final O a(Class cls) {
        O oX;
        Class cls2;
        AbstractC1209v.a(cls, "messageType");
        ConcurrentHashMap concurrentHashMap = this.b;
        O o = (O) concurrentHashMap.get(cls);
        if (o != null) {
            return o;
        }
        A a = this.a;
        a.getClass();
        Class cls3 = P.a;
        if (!AbstractC1206s.class.isAssignableFrom(cls) && (cls2 = P.a) != null && !cls2.isAssignableFrom(cls)) {
            throw new IllegalArgumentException("Message classes must extend GeneratedMessage or GeneratedMessageLite");
        }
        N nA = ((C1213z) a.a).a(cls);
        if ((nA.d & 2) == 2) {
            boolean zIsAssignableFrom = AbstractC1206s.class.isAssignableFrom(cls);
            AbstractC1206s abstractC1206s = nA.a;
            if (zIsAssignableFrom) {
                oX = new H(P.c, AbstractC1202n.a, abstractC1206s);
            } else {
                Q q = P.b;
                C1201m c1201m = AbstractC1202n.b;
                if (c1201m == null) {
                    throw new IllegalStateException("Protobuf runtime is not correctly loaded.");
                }
                oX = new H(q, c1201m, abstractC1206s);
            }
        } else if (AbstractC1206s.class.isAssignableFrom(cls)) {
            C1201m c1201m2 = null;
            I i = J.b;
            C1211x c1211x = AbstractC1212y.b;
            T t = P.c;
            if (AbstractC0147y.k(nA.a()) != 1) {
                c1201m2 = AbstractC1202n.a;
            }
            C1201m c1201m3 = c1201m2;
            C c2 = D.b;
            int[] iArr = G.n;
            if (!(nA instanceof N)) {
                nA.getClass();
                throw new ClassCastException();
            }
            oX = G.x(nA, i, c1211x, t, c1201m3, c2);
        } else {
            C1201m c1201m4 = null;
            I i2 = J.a;
            C1211x c1211x2 = AbstractC1212y.a;
            Q q2 = P.b;
            if (AbstractC0147y.k(nA.a()) != 1 && (c1201m4 = AbstractC1202n.b) == null) {
                throw new IllegalStateException("Protobuf runtime is not correctly loaded.");
            }
            C1201m c1201m5 = c1201m4;
            C c3 = D.a;
            int[] iArr2 = G.n;
            if (!(nA instanceof N)) {
                nA.getClass();
                throw new ClassCastException();
            }
            oX = G.x(nA, i2, c1211x2, q2, c1201m5, c3);
        }
        O o2 = (O) concurrentHashMap.putIfAbsent(cls, oX);
        return o2 != null ? o2 : oX;
    }
}
