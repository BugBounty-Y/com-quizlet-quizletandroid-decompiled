package com.mayakapps.kache;

import java.util.Set;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class w {
    public final Set a;
    public final Set b;

    public w(Set keys, Set underCreationKeys) {
        Intrinsics.checkNotNullParameter(keys, "keys");
        Intrinsics.checkNotNullParameter(underCreationKeys, "underCreationKeys");
        this.a = keys;
        this.b = underCreationKeys;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof w)) {
            return false;
        }
        w wVar = (w) obj;
        return Intrinsics.b(this.a, wVar.a) && Intrinsics.b(this.b, wVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "KacheKeys(keys=" + this.a + ", underCreationKeys=" + this.b + ')';
    }
}
