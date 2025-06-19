package retrofit2;

import java.lang.reflect.Method;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class z extends S {
    public final /* synthetic */ int d;
    public final Method e;
    public final int f;

    public /* synthetic */ z(Method method, int i, int i2) {
        this.d = i2;
        this.e = method;
        this.f = i;
    }

    @Override // retrofit2.S
    public final void a(H h, Object obj) {
        switch (this.d) {
            case 0:
                okhttp3.r headers = (okhttp3.r) obj;
                if (headers == null) {
                    throw S.p(this.e, this.f, "Headers parameter must not be null.", new Object[0]);
                }
                com.android.billingclient.api.h hVar = h.f;
                hVar.getClass();
                Intrinsics.checkNotNullParameter(headers, "headers");
                int size = headers.size();
                for (int i = 0; i < size; i++) {
                    hVar.b(headers.b(i), headers.g(i));
                }
                return;
            default:
                if (obj == null) {
                    throw S.p(this.e, this.f, "@Url parameter is null.", new Object[0]);
                }
                h.c = obj.toString();
                return;
        }
    }
}
