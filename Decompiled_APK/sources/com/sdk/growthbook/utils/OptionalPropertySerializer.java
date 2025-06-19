package com.sdk.growthbook.utils;

import com.sdk.growthbook.utils.OptionalProperty;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.SerializationException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public class OptionalPropertySerializer<T> implements KSerializer {

    @NotNull
    private final SerialDescriptor descriptor;

    @NotNull
    private final KSerializer valueSerializer;

    public OptionalPropertySerializer(@NotNull KSerializer valueSerializer) {
        Intrinsics.checkNotNullParameter(valueSerializer, "valueSerializer");
        this.valueSerializer = valueSerializer;
        this.descriptor = valueSerializer.getDescriptor();
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final SerialDescriptor getDescriptor() {
        return this.descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final OptionalProperty<T> deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        return new OptionalProperty.Present(this.valueSerializer.deserialize(decoder));
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(@NotNull Encoder encoder, @NotNull OptionalProperty<? extends T> value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        if (Intrinsics.b(value, OptionalProperty.NotPresent.INSTANCE)) {
            throw new SerializationException("Tried to serialize an optional property that had no value present. Is encodeDefaults false?");
        }
        if (!(value instanceof OptionalProperty.Present)) {
            throw new NoWhenBranchMatchedException();
        }
        this.valueSerializer.serialize(encoder, ((OptionalProperty.Present) value).getValue());
    }
}
