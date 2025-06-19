package com.google.android.gms.internal.ads;

import java.nio.charset.Charset;
import java.util.concurrent.ConcurrentHashMap;

/* renamed from: com.google.android.gms.internal.ads.lB, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2305lB {
    public static final C2305lB c = new C2305lB();
    public final ConcurrentHashMap b = new ConcurrentHashMap();
    public final Os a = new Os(1);

    public final InterfaceC2562rB a(Class cls) {
        InterfaceC2562rB interfaceC2562rBA;
        Charset charset = WA.a;
        if (cls == null) {
            throw new NullPointerException("messageType");
        }
        ConcurrentHashMap concurrentHashMap = this.b;
        InterfaceC2562rB interfaceC2562rB = (InterfaceC2562rB) concurrentHashMap.get(cls);
        if (interfaceC2562rB != null) {
            return interfaceC2562rB;
        }
        Os os = this.a;
        os.getClass();
        C1 c1 = AbstractC2605sB.a;
        OA.class.isAssignableFrom(cls);
        C2391nB c2391nBC = ((Lr) os.b).c(cls);
        if ((c2391nBC.d & 2) == 2) {
            C1 c12 = AbstractC2605sB.a;
            C2806wy c2806wy = JA.a;
            interfaceC2562rBA = new C2133hB(c12, c2391nBC.a);
        } else {
            int i = AbstractC2177iB.a;
            int i2 = ZA.a;
            C1 c13 = AbstractC2605sB.a;
            C2806wy c2806wy2 = c2391nBC.a() + (-1) != 1 ? JA.a : null;
            int i3 = AbstractC1914cB.a;
            interfaceC2562rBA = C2089gB.A(c2391nBC, c13, c2806wy2);
        }
        InterfaceC2562rB interfaceC2562rB2 = (InterfaceC2562rB) concurrentHashMap.putIfAbsent(cls, interfaceC2562rBA);
        return interfaceC2562rB2 != null ? interfaceC2562rB2 : interfaceC2562rBA;
    }
}
