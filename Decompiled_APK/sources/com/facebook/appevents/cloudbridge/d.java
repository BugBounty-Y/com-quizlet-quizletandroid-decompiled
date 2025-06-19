package com.facebook.appevents.cloudbridge;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d {
    public final k a;
    public final i b;

    public d(k kVar, i field) {
        Intrinsics.checkNotNullParameter(field, "field");
        this.a = kVar;
        this.b = field;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a == dVar.a && this.b == dVar.b;
    }

    public final int hashCode() {
        k kVar = this.a;
        return this.b.hashCode() + ((kVar == null ? 0 : kVar.hashCode()) * 31);
    }

    public final String toString() {
        return "SectionCustomEventFieldMapping(section=" + this.a + ", field=" + this.b + ')';
    }
}
