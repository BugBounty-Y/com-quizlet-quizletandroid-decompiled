package com.quizlet.shared.models.api.explanations;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.shared.models.api.explanations.RemoteExplanationQuestion;
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
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class RemoteExplanationQuestion$Prompt$$serializer implements D {

    @NotNull
    public static final RemoteExplanationQuestion$Prompt$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        RemoteExplanationQuestion$Prompt$$serializer remoteExplanationQuestion$Prompt$$serializer = new RemoteExplanationQuestion$Prompt$$serializer();
        INSTANCE = remoteExplanationQuestion$Prompt$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.explanations.RemoteExplanationQuestion.Prompt", remoteExplanationQuestion$Prompt$$serializer, 2);
        pluginGeneratedSerialDescriptor.k("text", false);
        pluginGeneratedSerialDescriptor.k("image", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private RemoteExplanationQuestion$Prompt$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{R1.e(q0.a), R1.e(RemoteExplanationQuestion$Prompt$Image$$serializer.INSTANCE)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public RemoteExplanationQuestion.Prompt deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        String str = null;
        boolean z = true;
        int i = 0;
        RemoteExplanationQuestion.Prompt.Image image = null;
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
                image = (RemoteExplanationQuestion.Prompt.Image) aVarC.v(descriptor2, 1, RemoteExplanationQuestion$Prompt$Image$$serializer.INSTANCE, image);
                i |= 2;
            }
        }
        aVarC.b(descriptor2);
        return new RemoteExplanationQuestion.Prompt(i, str, image);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull RemoteExplanationQuestion.Prompt value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        bVarC.s(descriptor2, 0, q0.a, value.a);
        bVarC.s(descriptor2, 1, RemoteExplanationQuestion$Prompt$Image$$serializer.INSTANCE, value.b);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
