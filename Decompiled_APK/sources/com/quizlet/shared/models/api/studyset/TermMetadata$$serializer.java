package com.quizlet.shared.models.api.studyset;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.UnknownFieldException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class TermMetadata$$serializer implements D {

    @NotNull
    public static final TermMetadata$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        TermMetadata$$serializer termMetadata$$serializer = new TermMetadata$$serializer();
        INSTANCE = termMetadata$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.studyset.TermMetadata", termMetadata$$serializer, 2);
        pluginGeneratedSerialDescriptor.k("word", true);
        pluginGeneratedSerialDescriptor.k("definition", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private TermMetadata$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        q0 q0Var = q0.a;
        return new KSerializer[]{R1.e(q0Var), R1.e(q0Var)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public TermMetadata deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        String str = null;
        boolean z = true;
        int i = 0;
        String str2 = null;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                str = (String) aVarC.v(descriptor2, 0, q0.a, str);
                i |= 1;
            } else {
                if (iT != 1) {
                    throw new UnknownFieldException(iT);
                }
                str2 = (String) aVarC.v(descriptor2, 1, q0.a, str2);
                i |= 2;
            }
        }
        aVarC.b(descriptor2);
        return new TermMetadata(i, str, str2);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull TermMetadata value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        if (bVarC.D(descriptor2) || value.a != null) {
            bVarC.s(descriptor2, 0, q0.a, value.a);
        }
        if (bVarC.D(descriptor2) || value.b != null) {
            bVarC.s(descriptor2, 1, q0.a, value.b);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
