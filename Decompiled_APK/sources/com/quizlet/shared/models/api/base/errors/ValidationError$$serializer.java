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
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class ValidationError$$serializer implements D {

    @NotNull
    public static final ValidationError$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        ValidationError$$serializer validationError$$serializer = new ValidationError$$serializer();
        INSTANCE = validationError$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.base.errors.ValidationError", validationError$$serializer, 3);
        pluginGeneratedSerialDescriptor.k("identifier", false);
        pluginGeneratedSerialDescriptor.k("message", false);
        pluginGeneratedSerialDescriptor.k("field", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private ValidationError$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        q0 q0Var = q0.a;
        return new KSerializer[]{q0Var, q0Var, R1.e(q0Var)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public ValidationError deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        String strR = null;
        boolean z = true;
        int i = 0;
        String strR2 = null;
        String str = null;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                strR = aVarC.r(descriptor2, 0);
                i |= 1;
            } else if (iT == 1) {
                strR2 = aVarC.r(descriptor2, 1);
                i |= 2;
            } else {
                if (iT != 2) {
                    throw new UnknownFieldException(iT);
                }
                str = (String) aVarC.v(descriptor2, 2, q0.a, str);
                i |= 4;
            }
        }
        aVarC.b(descriptor2);
        return new ValidationError(strR, i, strR2, str);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull ValidationError value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        bVarC.r(descriptor2, 0, value.a);
        bVarC.r(descriptor2, 1, value.b);
        bVarC.s(descriptor2, 2, q0.a, value.c);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
