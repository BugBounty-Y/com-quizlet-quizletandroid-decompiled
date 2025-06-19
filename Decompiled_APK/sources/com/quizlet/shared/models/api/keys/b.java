package com.quizlet.shared.models.api.keys;

import assistantMode.enums.s;
import assistantMode.refactored.enums.StudiableContainerType$Companion;
import assistantMode.refactored.enums.j;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final long a;
    public final s b;
    public final Boolean c;

    public b(long j, s studiableMetadataType, Boolean bool) {
        j studiableContainerType = j.b;
        Intrinsics.checkNotNullParameter(studiableContainerType, "studiableContainerType");
        Intrinsics.checkNotNullParameter(studiableMetadataType, "studiableMetadataType");
        this.a = j;
        this.b = studiableMetadataType;
        this.c = bool;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        if (this.a != bVar.a) {
            return false;
        }
        StudiableContainerType$Companion studiableContainerType$Companion = j.Companion;
        return this.b == bVar.b && Intrinsics.b(this.c, bVar.c);
    }

    public final int hashCode() {
        int iHashCode = (this.b.hashCode() + ((j.b.hashCode() + (Long.hashCode(this.a) * 31)) * 31)) * 31;
        Boolean bool = this.c;
        return iHashCode + (bool == null ? 0 : bool.hashCode());
    }

    public final String toString() {
        return "StudiableMetadataKey(studiableContainerId=" + this.a + ", studiableContainerType=" + j.b + ", studiableMetadataType=" + this.b + ", isPolling=" + this.c + ")";
    }
}
