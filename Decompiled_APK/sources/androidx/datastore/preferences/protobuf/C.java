package androidx.datastore.preferences.protobuf;

import java.nio.charset.Charset;

/* loaded from: classes.dex */
public final class C {
    public static final r b = new r(1);
    public final Object a;

    public C(C1104k c1104k) {
        AbstractC1115w.a(c1104k, "output");
        this.a = c1104k;
        c1104k.b = this;
    }

    public void a(int i, Object obj, U u) {
        C1104k c1104k = (C1104k) this.a;
        c1104k.C(i, 3);
        u.e((AbstractC1094a) obj, c1104k.b);
        c1104k.C(i, 4);
    }

    public C() {
        Q q = Q.c;
        Object obj = b;
        try {
            obj = (I) Class.forName("androidx.datastore.preferences.protobuf.DescriptorMessageInfoFactory").getDeclaredMethod("getInstance", null).invoke(null, null);
        } catch (Exception unused) {
        }
        I[] iArr = {r.b, obj};
        B b2 = new B();
        b2.a = iArr;
        Charset charset = AbstractC1115w.a;
        this.a = b2;
    }
}
