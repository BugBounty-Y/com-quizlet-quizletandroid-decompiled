package com.quizlet.shared.repository.studiableContainer;

import assistantMode.refactored.enums.j;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class DirectStudiableContainerRef implements a {

    @NotNull
    public static final Companion Companion = new Companion();
    public final long a;
    public final j b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return DirectStudiableContainerRef$$serializer.INSTANCE;
        }
    }

    public DirectStudiableContainerRef(int i, long j, j containerType) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, DirectStudiableContainerRef$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = j;
        this.b = containerType;
        Intrinsics.checkNotNullParameter(containerType, "containerType");
        if (containerType == j.b) {
            return;
        }
        throw new IllegalArgumentException(("StudiableContainerType {" + containerType + "} is not a direct container of StudiableItems.").toString());
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof DirectStudiableContainerRef)) {
            return false;
        }
        DirectStudiableContainerRef directStudiableContainerRef = (DirectStudiableContainerRef) obj;
        return this.a == directStudiableContainerRef.a && this.b == directStudiableContainerRef.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "DirectStudiableContainerRef(id=" + this.a + ", containerType=" + this.b + ")";
    }
}
