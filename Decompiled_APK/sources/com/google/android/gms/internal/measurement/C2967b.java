package com.google.android.gms.internal.measurement;

import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.measurement.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2967b {
    public static final com.google.common.collect.o d = com.google.common.collect.o.m(3, "_syn", "_err", "_el");
    public String a;
    public final long b;
    public final HashMap c;

    public C2967b(String str, long j, HashMap map) {
        this.a = str;
        this.b = j;
        HashMap map2 = new HashMap();
        this.c = map2;
        if (map != null) {
            map2.putAll(map);
        }
    }

    public static Object b(String str, Object obj, Object obj2) {
        if (d.contains(str) && (obj2 instanceof Double)) {
            return Long.valueOf(Math.round(((Double) obj2).doubleValue()));
        }
        if (str.startsWith("_")) {
            if (!(obj instanceof String) && obj != null) {
                return obj;
            }
        } else if (!(obj instanceof Double)) {
            if (obj instanceof Long) {
                return Long.valueOf(Math.round(((Double) obj2).doubleValue()));
            }
            if (obj instanceof String) {
                return obj2.toString();
            }
        }
        return obj2;
    }

    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public final C2967b clone() {
        return new C2967b(this.a, this.b, new HashMap(this.c));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C2967b)) {
            return false;
        }
        C2967b c2967b = (C2967b) obj;
        if (this.b == c2967b.b && this.a.equals(c2967b.a)) {
            return this.c.equals(c2967b.c);
        }
        return false;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        HashMap map = this.c;
        long j = this.b;
        return map.hashCode() + ((iHashCode + ((int) (j ^ (j >>> 32)))) * 31);
    }

    public final String toString() {
        String str = this.a;
        String string = this.c.toString();
        StringBuilder sbY = android.support.v4.media.session.a.y("Event{name='", str, "', timestamp=");
        sbY.append(this.b);
        sbY.append(", params=");
        sbY.append(string);
        sbY.append("}");
        return sbY.toString();
    }
}
