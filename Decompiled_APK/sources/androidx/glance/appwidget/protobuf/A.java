package androidx.glance.appwidget.protobuf;

import java.nio.charset.Charset;

/* loaded from: classes.dex */
public final class A {
    public static final C1204p b = new C1204p(1);
    public final Object a;

    public A(C1198j c1198j) {
        Charset charset = AbstractC1209v.a;
        this.a = c1198j;
        c1198j.b = this;
    }

    public void a(int i, Object obj, O o) {
        C1198j c1198j = (C1198j) this.a;
        c1198j.z(i, 3);
        o.h((AbstractC1189a) obj, c1198j.b);
        c1198j.z(i, 4);
    }

    public A() {
        L l = L.c;
        Object obj = b;
        try {
            obj = (E) Class.forName("androidx.glance.appwidget.protobuf.DescriptorMessageInfoFactory").getDeclaredMethod("getInstance", null).invoke(null, null);
        } catch (Exception unused) {
        }
        E[] eArr = {C1204p.b, obj};
        C1213z c1213z = new C1213z();
        c1213z.a = eArr;
        Charset charset = AbstractC1209v.a;
        this.a = c1213z;
    }
}
