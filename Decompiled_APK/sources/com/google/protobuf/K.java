package com.google.protobuf;

import java.nio.charset.Charset;

/* loaded from: classes2.dex */
public final class K {
    public static final C4024s b = new C4024s(1);
    public final Object a;

    public K(AbstractC4018l abstractC4018l) {
        C.a(abstractC4018l, "output");
        this.a = abstractC4018l;
        abstractC4018l.c = this;
    }

    public void a(int i, Object obj, InterfaceC4009c0 interfaceC4009c0) {
        AbstractC4018l abstractC4018l = (AbstractC4018l) this.a;
        abstractC4018l.C(i, 3);
        interfaceC4009c0.e((AbstractC4004a) obj, abstractC4018l.c);
        abstractC4018l.C(i, 4);
    }

    public K() {
        Q q;
        try {
            q = (Q) Class.forName("com.google.protobuf.DescriptorMessageInfoFactory").getDeclaredMethod("getInstance", null).invoke(null, null);
        } catch (Exception unused) {
            q = b;
        }
        Q[] qArr = {C4024s.b, q};
        J j = new J();
        j.a = qArr;
        Charset charset = C.a;
        this.a = j;
    }
}
