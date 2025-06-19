package retrofit2;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3343g2;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Map;

/* loaded from: classes3.dex */
public final class A extends S {
    public final /* synthetic */ int d = 0;
    public final Method e;
    public final int f;
    public final InterfaceC5186k g;
    public final Object h;

    public A(Method method, int i, okhttp3.r rVar, InterfaceC5186k interfaceC5186k) {
        this.e = method;
        this.f = i;
        this.h = rVar;
        this.g = interfaceC5186k;
    }

    @Override // retrofit2.S
    public final void a(H h, Object obj) {
        switch (this.d) {
            case 0:
                if (obj == null) {
                    return;
                }
                try {
                    h.c((okhttp3.r) this.h, (okhttp3.F) this.g.convert(obj));
                    return;
                } catch (IOException e) {
                    throw S.p(this.e, this.f, "Unable to convert " + obj + " to RequestBody", e);
                }
            default:
                Map map = (Map) obj;
                Method method = this.e;
                int i = this.f;
                if (map == null) {
                    throw S.p(method, i, "Part map was null.", new Object[0]);
                }
                for (Map.Entry entry : map.entrySet()) {
                    String str = (String) entry.getKey();
                    if (str == null) {
                        throw S.p(method, i, "Part map contained null key.", new Object[0]);
                    }
                    Object value = entry.getValue();
                    if (value == null) {
                        throw S.p(method, i, android.support.v4.media.session.a.B("Part map contained null value for key '", str, "'."), new Object[0]);
                    }
                    h.c(AbstractC3343g2.d("Content-Disposition", android.support.v4.media.session.a.B("form-data; name=\"", str, "\""), "Content-Transfer-Encoding", (String) this.h), (okhttp3.F) this.g.convert(value));
                }
                return;
        }
    }

    public A(Method method, int i, InterfaceC5186k interfaceC5186k, String str) {
        this.e = method;
        this.f = i;
        this.g = interfaceC5186k;
        this.h = str;
    }
}
