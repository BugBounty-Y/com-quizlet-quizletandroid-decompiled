package com.google.protobuf;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.concurrent.ConcurrentHashMap;

/* loaded from: classes2.dex */
public final class Z {
    public static final Z c = new Z();
    public final ConcurrentHashMap b = new ConcurrentHashMap();
    public final K a = new K();

    public final InterfaceC4009c0 a(Class cls) {
        InterfaceC4009c0 interfaceC4009c0Y;
        Class cls2;
        C.a(cls, "messageType");
        ConcurrentHashMap concurrentHashMap = this.b;
        InterfaceC4009c0 interfaceC4009c0 = (InterfaceC4009c0) concurrentHashMap.get(cls);
        if (interfaceC4009c0 != null) {
            return interfaceC4009c0;
        }
        K k = this.a;
        k.getClass();
        Class cls3 = d0.a;
        if (!AbstractC4027v.class.isAssignableFrom(cls) && (cls2 = d0.a) != null && !cls2.isAssignableFrom(cls)) {
            throw new IllegalArgumentException("Message classes must extend GeneratedMessage or GeneratedMessageLite");
        }
        C4007b0 c4007b0A = ((J) k.a).a(cls);
        if ((c4007b0A.d & 2) == 2) {
            boolean zIsAssignableFrom = AbstractC4027v.class.isAssignableFrom(cls);
            AbstractC4004a abstractC4004a = c4007b0A.a;
            if (zIsAssignableFrom) {
                interfaceC4009c0Y = new U(d0.c, AbstractC4022p.a, abstractC4004a);
            } else {
                j0 j0Var = d0.b;
                C4021o c4021o = AbstractC4022p.b;
                if (c4021o == null) {
                    throw new IllegalStateException("Protobuf runtime is not correctly loaded.");
                }
                interfaceC4009c0Y = new U(j0Var, c4021o, abstractC4004a);
            }
        } else if (AbstractC4027v.class.isAssignableFrom(cls)) {
            interfaceC4009c0Y = AbstractC0147y.k(c4007b0A.a()) != 1 ? T.y(c4007b0A, W.b, I.b, d0.c, AbstractC4022p.a, P.b) : T.y(c4007b0A, W.b, I.b, d0.c, null, P.b);
        } else if (AbstractC0147y.k(c4007b0A.a()) != 1) {
            V v = W.a;
            G g = I.a;
            j0 j0Var2 = d0.b;
            C4021o c4021o2 = AbstractC4022p.b;
            if (c4021o2 == null) {
                throw new IllegalStateException("Protobuf runtime is not correctly loaded.");
            }
            interfaceC4009c0Y = T.y(c4007b0A, v, g, j0Var2, c4021o2, P.a);
        } else {
            interfaceC4009c0Y = T.y(c4007b0A, W.a, I.a, d0.b, null, P.a);
        }
        InterfaceC4009c0 interfaceC4009c02 = (InterfaceC4009c0) concurrentHashMap.putIfAbsent(cls, interfaceC4009c0Y);
        return interfaceC4009c02 != null ? interfaceC4009c02 : interfaceC4009c0Y;
    }
}
