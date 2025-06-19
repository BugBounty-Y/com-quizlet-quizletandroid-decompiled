package okhttp3;

/* loaded from: classes3.dex */
public final class G {
    public C a;
    public B b;
    public String d;
    public q e;
    public J g;
    public H h;
    public H i;
    public H j;
    public long k;
    public long l;
    public androidx.compose.material.ripple.r m;
    public int c = -1;
    public com.android.billingclient.api.h f = new com.android.billingclient.api.h(3);

    public static void b(String str, H h) {
        if (h != null) {
            if (h.g != null) {
                throw new IllegalArgumentException(str.concat(".body != null").toString());
            }
            if (h.h != null) {
                throw new IllegalArgumentException(str.concat(".networkResponse != null").toString());
            }
            if (h.i != null) {
                throw new IllegalArgumentException(str.concat(".cacheResponse != null").toString());
            }
            if (h.j != null) {
                throw new IllegalArgumentException(str.concat(".priorResponse != null").toString());
            }
        }
    }

    public final H a() {
        int i = this.c;
        if (i < 0) {
            throw new IllegalStateException(("code < 0: " + this.c).toString());
        }
        C c = this.a;
        if (c == null) {
            throw new IllegalStateException("request == null");
        }
        B b = this.b;
        if (b == null) {
            throw new IllegalStateException("protocol == null");
        }
        String str = this.d;
        if (str != null) {
            return new H(c, b, str, i, this.e, this.f.d(), this.g, this.h, this.i, this.j, this.k, this.l, this.m);
        }
        throw new IllegalStateException("message == null");
    }
}
