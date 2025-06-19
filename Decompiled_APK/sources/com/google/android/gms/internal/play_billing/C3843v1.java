package com.google.android.gms.internal.play_billing;

import java.nio.charset.Charset;
import java.util.concurrent.ConcurrentHashMap;

/* renamed from: com.google.android.gms.internal.play_billing.v1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3843v1 {
    public static final C3843v1 c = new C3843v1();
    public final ConcurrentHashMap b = new ConcurrentHashMap();
    public final C3817m1 a = new C3817m1();

    public final InterfaceC3852y1 a(Class cls) {
        InterfaceC3852y1 interfaceC3852y1T;
        Charset charset = AbstractC3802h1.a;
        if (cls == null) {
            throw new NullPointerException("messageType");
        }
        ConcurrentHashMap concurrentHashMap = this.b;
        InterfaceC3852y1 interfaceC3852y1 = (InterfaceC3852y1) concurrentHashMap.get(cls);
        if (interfaceC3852y1 != null) {
            return interfaceC3852y1;
        }
        C3817m1 c3817m1 = this.a;
        c3817m1.getClass();
        C3781a1 c3781a1 = AbstractC3855z1.a;
        AbstractC3787c1.class.isAssignableFrom(cls);
        C3849x1 c3849x1C = ((C3817m1) c3817m1.a).c(cls);
        if ((c3849x1C.d & 2) == 2) {
            C3781a1 c3781a12 = AbstractC3855z1.a;
            C3781a1 c3781a13 = X0.a;
            interfaceC3852y1T = new C3834s1(c3781a12, c3849x1C.a);
        } else {
            int i = AbstractC3837t1.a;
            int i2 = AbstractC3814l1.a;
            C3781a1 c3781a14 = AbstractC3855z1.a;
            C3781a1 c3781a15 = c3849x1C.a() + (-1) != 1 ? X0.a : null;
            int i3 = AbstractC3823o1.a;
            interfaceC3852y1T = C3831r1.t(c3849x1C, c3781a14, c3781a15);
        }
        InterfaceC3852y1 interfaceC3852y12 = (InterfaceC3852y1) concurrentHashMap.putIfAbsent(cls, interfaceC3852y1T);
        return interfaceC3852y12 == null ? interfaceC3852y1T : interfaceC3852y12;
    }
}
