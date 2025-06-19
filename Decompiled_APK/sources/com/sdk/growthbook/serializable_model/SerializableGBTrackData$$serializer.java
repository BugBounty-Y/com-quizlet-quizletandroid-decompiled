package com.sdk.growthbook.serializable_model;

import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.UnknownFieldException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.encoding.a;
import kotlinx.serialization.encoding.b;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public /* synthetic */ class SerializableGBTrackData$$serializer implements D {

    @NotNull
    public static final SerializableGBTrackData$$serializer INSTANCE;

    @NotNull
    private static final SerialDescriptor descriptor;

    static {
        SerializableGBTrackData$$serializer serializableGBTrackData$$serializer = new SerializableGBTrackData$$serializer();
        INSTANCE = serializableGBTrackData$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.sdk.growthbook.serializable_model.SerializableGBTrackData", serializableGBTrackData$$serializer, 2);
        pluginGeneratedSerialDescriptor.k("experiment", false);
        pluginGeneratedSerialDescriptor.k("result", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private SerializableGBTrackData$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public final KSerializer[] childSerializers() {
        return new KSerializer[]{SerializableGBExperiment$$serializer.INSTANCE, SerializableGBExperimentResult$$serializer.INSTANCE};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final SerializableGBTrackData deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor serialDescriptor = descriptor;
        a aVarC = decoder.c(serialDescriptor);
        boolean z = true;
        int i = 0;
        SerializableGBExperiment serializableGBExperiment = null;
        SerializableGBExperimentResult serializableGBExperimentResult = null;
        while (z) {
            int iT = aVarC.t(serialDescriptor);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                serializableGBExperiment = (SerializableGBExperiment) aVarC.z(serialDescriptor, 0, SerializableGBExperiment$$serializer.INSTANCE, serializableGBExperiment);
                i |= 1;
            } else {
                if (iT != 1) {
                    throw new UnknownFieldException(iT);
                }
                serializableGBExperimentResult = (SerializableGBExperimentResult) aVarC.z(serialDescriptor, 1, SerializableGBExperimentResult$$serializer.INSTANCE, serializableGBExperimentResult);
                i |= 2;
            }
        }
        aVarC.b(serialDescriptor);
        return new SerializableGBTrackData(i, serializableGBExperiment, serializableGBExperimentResult, null);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(@NotNull Encoder encoder, @NotNull SerializableGBTrackData value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor serialDescriptor = descriptor;
        b bVarC = encoder.c(serialDescriptor);
        SerializableGBTrackData.write$Self$GrowthBook_release(value, bVarC, serialDescriptor);
        bVarC.b(serialDescriptor);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
