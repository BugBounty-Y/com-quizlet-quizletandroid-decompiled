package io.ktor.http;

import java.util.LinkedHashMap;
import java.util.List;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class y {
    public static final y c;
    public static final LinkedHashMap d;
    public final String a;
    public final int b;

    static {
        y yVar = new y("http", 80);
        c = yVar;
        List listJ = B.j(yVar, new y("https", 443), new y("ws", 80), new y("wss", 443), new y("socks", 1080));
        int iA = U.a(C.q(listJ, 10));
        if (iA < 16) {
            iA = 16;
        }
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
        for (Object obj : listJ) {
            linkedHashMap.put(((y) obj).a, obj);
        }
        d = linkedHashMap;
    }

    public y(String name, int i) {
        Intrinsics.checkNotNullParameter(name, "name");
        this.a = name;
        this.b = i;
        for (int i2 = 0; i2 < name.length(); i2++) {
            char cCharAt = name.charAt(i2);
            if (Character.toLowerCase(cCharAt) != cCharAt) {
                throw new IllegalArgumentException("All characters should be lower case");
            }
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof y)) {
            return false;
        }
        y yVar = (y) obj;
        return Intrinsics.b(this.a, yVar.a) && this.b == yVar.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("URLProtocol(name=");
        sb.append(this.a);
        sb.append(", defaultPort=");
        return android.support.v4.media.session.a.q(sb, this.b, ')');
    }
}
