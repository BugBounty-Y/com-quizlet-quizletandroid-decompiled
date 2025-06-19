package com.quizlet.shared.models.api.base.errors;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
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
public final class QuizletApiError$$serializer implements D {

    @NotNull
    public static final QuizletApiError$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        QuizletApiError$$serializer quizletApiError$$serializer = new QuizletApiError$$serializer();
        INSTANCE = quizletApiError$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.base.errors.QuizletApiError", quizletApiError$$serializer, 3);
        pluginGeneratedSerialDescriptor.k("message", true);
        pluginGeneratedSerialDescriptor.k("identifier", true);
        pluginGeneratedSerialDescriptor.k("code", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private QuizletApiError$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        q0 q0Var = q0.a;
        return new KSerializer[]{R1.e(q0Var), R1.e(q0Var), R1.e(K.a)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public QuizletApiError deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        String str = null;
        boolean z = true;
        int i = 0;
        String str2 = null;
        Integer num = null;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                str = (String) aVarC.v(descriptor2, 0, q0.a, str);
                i |= 1;
            } else if (iT == 1) {
                str2 = (String) aVarC.v(descriptor2, 1, q0.a, str2);
                i |= 2;
            } else {
                if (iT != 2) {
                    throw new UnknownFieldException(iT);
                }
                num = (Integer) aVarC.v(descriptor2, 2, K.a, num);
                i |= 4;
            }
        }
        aVarC.b(descriptor2);
        return new QuizletApiError(str, str2, num, i);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull QuizletApiError value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        if (bVarC.D(descriptor2) || value.a != null) {
            bVarC.s(descriptor2, 0, q0.a, value.a);
        }
        if (bVarC.D(descriptor2) || value.b != null) {
            bVarC.s(descriptor2, 1, q0.a, value.b);
        }
        if (bVarC.D(descriptor2) || value.c != null) {
            bVarC.s(descriptor2, 2, K.a, value.c);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
