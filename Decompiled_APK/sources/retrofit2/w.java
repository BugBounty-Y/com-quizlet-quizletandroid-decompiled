package retrofit2;

import java.io.IOException;
import java.lang.reflect.Method;

/* loaded from: classes3.dex */
public final class w extends S {
    public final Method d;
    public final int e;
    public final InterfaceC5186k f;

    public w(Method method, int i, InterfaceC5186k interfaceC5186k) {
        this.d = method;
        this.e = i;
        this.f = interfaceC5186k;
    }

    @Override // retrofit2.S
    public final void a(H h, Object obj) {
        Method method = this.d;
        int i = this.e;
        if (obj == null) {
            throw S.p(method, i, "Body parameter value must not be null.", new Object[0]);
        }
        try {
            h.k = (okhttp3.F) this.f.convert(obj);
        } catch (IOException e) {
            throw S.q(method, e, i, "Unable to convert " + obj + " to RequestBody", new Object[0]);
        }
    }
}
