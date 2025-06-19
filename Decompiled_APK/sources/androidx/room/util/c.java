package androidx.room.util;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c implements Comparable {
    public final int a;
    public final int b;
    public final String c;
    public final String d;

    public c(String from, int i, String to, int i2) {
        Intrinsics.checkNotNullParameter(from, "from");
        Intrinsics.checkNotNullParameter(to, "to");
        this.a = i;
        this.b = i2;
        this.c = from;
        this.d = to;
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        c other = (c) obj;
        Intrinsics.checkNotNullParameter(other, "other");
        int i = this.a - other.a;
        return i == 0 ? this.b - other.b : i;
    }
}
