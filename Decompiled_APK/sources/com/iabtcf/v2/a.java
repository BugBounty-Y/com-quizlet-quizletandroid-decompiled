package com.iabtcf.v2;

import com.iabtcf.utils.b;
import com.iabtcf.utils.c;
import java.util.Objects;
import java.util.StringJoiner;

/* loaded from: classes2.dex */
public class a {
    public final int a;
    public final int b;
    public final c c;

    public a(int i, int i2, c cVar) {
        if (i2 == 0) {
            throw null;
        }
        this.a = i;
        this.b = i2;
        this.c = cVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && this.b == aVar.b && this.c.equals(aVar.c);
    }

    public final int hashCode() {
        Integer numValueOf = Integer.valueOf(this.a);
        c cVar = this.c;
        int i = this.b;
        return Objects.hash(numValueOf, i == 0 ? null : Integer.valueOf(i - 1), cVar);
    }

    public final String toString() {
        StringJoiner stringJoiner = new StringJoiner(", ", "[", "]");
        c cVar = this.c;
        cVar.getClass();
        b bVar = new b(cVar);
        while (bVar.hasNext()) {
            stringJoiner.add(bVar.next().toString());
        }
        StringBuilder sb = new StringBuilder("PublisherRestriction{purposeId=");
        sb.append(this.a);
        sb.append(", restrictionType=");
        int i = this.b;
        sb.append(i != 1 ? i != 2 ? i != 3 ? i != 4 ? "null" : "UNDEFINED" : "REQUIRE_LEGITIMATE_INTEREST" : "REQUIRE_CONSENT" : "NOT_ALLOWED");
        sb.append(", vendorIds=");
        sb.append(stringJoiner.toString());
        sb.append('}');
        return sb.toString();
    }
}
