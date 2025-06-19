package retrofit2;

import java.util.Objects;

/* loaded from: classes3.dex */
public class HttpException extends RuntimeException {
    public final int a;
    public final String b;
    public final transient K c;

    public HttpException(K k) {
        Objects.requireNonNull(k, "response == null");
        StringBuilder sb = new StringBuilder("HTTP ");
        okhttp3.H h = k.a;
        sb.append(h.d);
        sb.append(" ");
        sb.append(h.c);
        super(sb.toString());
        this.a = h.d;
        this.b = h.c;
        this.c = k;
    }
}
