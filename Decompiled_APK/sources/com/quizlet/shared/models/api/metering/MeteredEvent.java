package com.quizlet.shared.models.api.metering;

import android.support.v4.media.session.a;
import kotlin.Metadata;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class MeteredEvent {

    @NotNull
    public static final Companion Companion = new Companion();
    public final int a;
    public final int b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return MeteredEvent$$serializer.INSTANCE;
        }
    }

    public MeteredEvent(int i, int i2) {
        this.a = i;
        this.b = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof MeteredEvent)) {
            return false;
        }
        MeteredEvent meteredEvent = (MeteredEvent) obj;
        return this.a == meteredEvent.a && this.b == meteredEvent.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MeteredEvent(numEvents=");
        sb.append(this.a);
        sb.append(", threshold=");
        return a.r(sb, this.b, ")");
    }

    public /* synthetic */ MeteredEvent(int i, int i2, int i3) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, MeteredEvent$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = i2;
        this.b = i3;
    }
}
