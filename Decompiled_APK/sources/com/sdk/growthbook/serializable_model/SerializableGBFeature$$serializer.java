package com.sdk.growthbook.serializable_model;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import java.util.List;
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
import kotlinx.serialization.internal.l0;
import kotlinx.serialization.json.k;
import kotlinx.serialization.json.m;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public /* synthetic */ class SerializableGBFeature$$serializer implements D {

    @NotNull
    public static final SerializableGBFeature$$serializer INSTANCE;

    @NotNull
    private static final SerialDescriptor descriptor;

    static {
        SerializableGBFeature$$serializer serializableGBFeature$$serializer = new SerializableGBFeature$$serializer();
        INSTANCE = serializableGBFeature$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.sdk.growthbook.serializable_model.SerializableGBFeature", serializableGBFeature$$serializer, 2);
        pluginGeneratedSerialDescriptor.k("defaultValue", true);
        pluginGeneratedSerialDescriptor.k("rules", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private SerializableGBFeature$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public final KSerializer[] childSerializers() {
        return new KSerializer[]{R1.e(m.a), R1.e(SerializableGBFeature.$childSerializers[1])};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final SerializableGBFeature deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor serialDescriptor = descriptor;
        a aVarC = decoder.c(serialDescriptor);
        KSerializer[] kSerializerArr = SerializableGBFeature.$childSerializers;
        boolean z = true;
        int i = 0;
        k kVar = null;
        List list = null;
        while (z) {
            int iT = aVarC.t(serialDescriptor);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                kVar = (k) aVarC.v(serialDescriptor, 0, m.a, kVar);
                i |= 1;
            } else {
                if (iT != 1) {
                    throw new UnknownFieldException(iT);
                }
                list = (List) aVarC.v(serialDescriptor, 1, kSerializerArr[1], list);
                i |= 2;
            }
        }
        aVarC.b(serialDescriptor);
        return new SerializableGBFeature(i, kVar, list, (l0) null);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public final SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public final void serialize(@NotNull Encoder encoder, @NotNull SerializableGBFeature value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor serialDescriptor = descriptor;
        b bVarC = encoder.c(serialDescriptor);
        SerializableGBFeature.write$Self$GrowthBook_release(value, bVarC, serialDescriptor);
        bVarC.b(serialDescriptor);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
