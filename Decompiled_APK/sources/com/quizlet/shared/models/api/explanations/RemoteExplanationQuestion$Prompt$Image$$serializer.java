package com.quizlet.shared.models.api.explanations;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
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
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class RemoteExplanationQuestion$Prompt$Image$$serializer implements D {

    @NotNull
    public static final RemoteExplanationQuestion$Prompt$Image$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        RemoteExplanationQuestion$Prompt$Image$$serializer remoteExplanationQuestion$Prompt$Image$$serializer = new RemoteExplanationQuestion$Prompt$Image$$serializer();
        INSTANCE = remoteExplanationQuestion$Prompt$Image$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.explanations.RemoteExplanationQuestion.Prompt.Image", remoteExplanationQuestion$Prompt$Image$$serializer, 3);
        pluginGeneratedSerialDescriptor.k("srcUrl", false);
        pluginGeneratedSerialDescriptor.k(OTUXParamsKeys.OT_UX_HEIGHT, false);
        pluginGeneratedSerialDescriptor.k(OTUXParamsKeys.OT_UX_WIDTH, false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private RemoteExplanationQuestion$Prompt$Image$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        K k = K.a;
        return new KSerializer[]{q0.a, R1.e(k), R1.e(k)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public RemoteExplanationQuestion.Prompt.Image deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        String strR = null;
        boolean z = true;
        int i = 0;
        Integer num = null;
        Integer num2 = null;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                strR = aVarC.r(descriptor2, 0);
                i |= 1;
            } else if (iT == 1) {
                num = (Integer) aVarC.v(descriptor2, 1, K.a, num);
                i |= 2;
            } else {
                if (iT != 2) {
                    throw new UnknownFieldException(iT);
                }
                num2 = (Integer) aVarC.v(descriptor2, 2, K.a, num2);
                i |= 4;
            }
        }
        aVarC.b(descriptor2);
        return new RemoteExplanationQuestion.Prompt.Image(i, strR, num, num2);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull RemoteExplanationQuestion.Prompt.Image value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        bVarC.r(descriptor2, 0, value.a);
        K k = K.a;
        bVarC.s(descriptor2, 1, k, value.b);
        bVarC.s(descriptor2, 2, k, value.c);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
