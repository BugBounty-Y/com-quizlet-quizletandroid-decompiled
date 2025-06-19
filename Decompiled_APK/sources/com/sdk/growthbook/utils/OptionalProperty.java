package com.sdk.growthbook.utils;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public abstract class OptionalProperty<T> {

    @Metadata
    public static final class NotPresent extends OptionalProperty {

        @NotNull
        public static final NotPresent INSTANCE = new NotPresent();

        private NotPresent() {
            super(null);
        }

        public boolean equals(Object obj) {
            return this == obj || (obj instanceof NotPresent);
        }

        public int hashCode() {
            return -1860197977;
        }

        @NotNull
        public String toString() {
            return "NotPresent";
        }
    }

    @Metadata
    public static final class Present<T> extends OptionalProperty<T> {
        private final T value;

        public Present(T t) {
            super(null);
            this.value = t;
        }

        /* JADX WARN: Multi-variable type inference failed */
        public static /* synthetic */ Present copy$default(Present present, Object obj, int i, Object obj2) {
            if ((i & 1) != 0) {
                obj = present.value;
            }
            return present.copy(obj);
        }

        public final T component1() {
            return this.value;
        }

        @NotNull
        public final Present<T> copy(T t) {
            return new Present<>(t);
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof Present) && Intrinsics.b(this.value, ((Present) obj).value);
        }

        public final T getValue() {
            return this.value;
        }

        public int hashCode() {
            T t = this.value;
            if (t == null) {
                return 0;
            }
            return t.hashCode();
        }

        @NotNull
        public String toString() {
            return "Present(value=" + this.value + ')';
        }
    }

    public /* synthetic */ OptionalProperty(DefaultConstructorMarker defaultConstructorMarker) {
        this();
    }

    private OptionalProperty() {
    }
}
