package com.google.android.gms.internal.measurement;

import java.nio.charset.Charset;
import java.util.concurrent.ConcurrentHashMap;

/* renamed from: com.google.android.gms.internal.measurement.s2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3054s2 {
    public static final C3054s2 c = new C3054s2();
    public final ConcurrentHashMap b = new ConcurrentHashMap();
    public final C3005i2 a = new C3005i2(0);

    public final InterfaceC3069v2 a(Class cls) {
        InterfaceC3069v2 interfaceC3069v2T;
        Charset charset = AbstractC2980d2.a;
        if (cls == null) {
            throw new NullPointerException("messageType");
        }
        ConcurrentHashMap concurrentHashMap = this.b;
        InterfaceC3069v2 interfaceC3069v2 = (InterfaceC3069v2) concurrentHashMap.get(cls);
        if (interfaceC3069v2 != null) {
            return interfaceC3069v2;
        }
        C3005i2 c3005i2 = this.a;
        c3005i2.getClass();
        U1 u1 = AbstractC3074w2.a;
        W1.class.isAssignableFrom(cls);
        C3064u2 c3064u2C = ((C3005i2) c3005i2.a).c(cls);
        if ((c3064u2C.d & 2) == 2) {
            U1 u12 = AbstractC3074w2.a;
            U1 u13 = R1.a;
            interfaceC3069v2T = new C3040p2(u12, c3064u2C.a);
        } else {
            int i = AbstractC3045q2.a;
            int i2 = AbstractC2995g2.a;
            U1 u14 = AbstractC3074w2.a;
            U1 u15 = c3064u2C.a() + (-1) != 1 ? R1.a : null;
            int i3 = AbstractC3020l2.a;
            interfaceC3069v2T = C3035o2.t(c3064u2C, u14, u15);
        }
        InterfaceC3069v2 interfaceC3069v22 = (InterfaceC3069v2) concurrentHashMap.putIfAbsent(cls, interfaceC3069v2T);
        return interfaceC3069v22 != null ? interfaceC3069v22 : interfaceC3069v2T;
    }
}
