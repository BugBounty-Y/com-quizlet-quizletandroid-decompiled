package okhttp3;

import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Pair;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class C {
    public final s a;
    public final String b;
    public final r c;
    public final F d;
    public final Map e;
    public C5074c f;

    public C(s url, String method, r headers, F f, Map tags) {
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(method, "method");
        Intrinsics.checkNotNullParameter(headers, "headers");
        Intrinsics.checkNotNullParameter(tags, "tags");
        this.a = url;
        this.b = method;
        this.c = headers;
        this.d = f;
        this.e = tags;
    }

    public final String a(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        return this.c.a(name);
    }

    public final com.quizlet.remote.model.notes.e b() {
        Intrinsics.checkNotNullParameter(this, "request");
        com.quizlet.remote.model.notes.e eVar = new com.quizlet.remote.model.notes.e(false);
        eVar.f = new LinkedHashMap();
        eVar.b = this.a;
        eVar.c = this.b;
        eVar.e = this.d;
        Map map = this.e;
        eVar.f = map.isEmpty() ? new LinkedHashMap() : V.m(map);
        eVar.d = this.c.e();
        return eVar;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Request{method=");
        sb.append(this.b);
        sb.append(", url=");
        sb.append(this.a);
        r rVar = this.c;
        if (rVar.size() != 0) {
            sb.append(", headers=[");
            int i = 0;
            for (Object obj : rVar) {
                int i2 = i + 1;
                if (i < 0) {
                    kotlin.collections.B.p();
                    throw null;
                }
                Pair pair = (Pair) obj;
                String str = (String) pair.a;
                String str2 = (String) pair.b;
                if (i > 0) {
                    sb.append(", ");
                }
                sb.append(str);
                sb.append(':');
                sb.append(str2);
                i = i2;
            }
            sb.append(']');
        }
        Map map = this.e;
        if (!map.isEmpty()) {
            sb.append(", tags=");
            sb.append(map);
        }
        sb.append('}');
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "StringBuilder().apply(builderAction).toString()");
        return string;
    }
}
