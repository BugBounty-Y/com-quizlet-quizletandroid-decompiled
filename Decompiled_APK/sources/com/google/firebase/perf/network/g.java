package com.google.firebase.perf.network;

import com.google.firebase.perf.v1.p;
import com.google.firebase.perf.v1.t;
import java.util.regex.Pattern;
import org.apache.http.Header;
import org.apache.http.HttpMessage;
import org.apache.http.HttpResponse;

/* loaded from: classes2.dex */
public abstract class g {
    public static final Pattern a = Pattern.compile("(^|.*\\s)datatransport/\\S+ android/($|\\s.*)");

    public static Long a(HttpMessage httpMessage) {
        try {
            Header firstHeader = httpMessage.getFirstHeader("content-length");
            if (firstHeader != null) {
                return Long.valueOf(Long.parseLong(firstHeader.getValue()));
            }
            return null;
        } catch (NumberFormatException unused) {
            com.google.firebase.perf.logging.a.d().a();
            return null;
        }
    }

    public static String b(HttpResponse httpResponse) {
        String value;
        Header firstHeader = httpResponse.getFirstHeader("content-type");
        if (firstHeader == null || (value = firstHeader.getValue()) == null) {
            return null;
        }
        return value;
    }

    public static void c(com.google.firebase.perf.metrics.d dVar) {
        if (!((t) dVar.d.b).W()) {
            p pVar = dVar.d;
            pVar.k();
            t.x((t) pVar.b);
        }
        dVar.b();
    }
}
