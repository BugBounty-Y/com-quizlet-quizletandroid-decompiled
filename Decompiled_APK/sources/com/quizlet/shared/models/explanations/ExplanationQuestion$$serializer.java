package com.quizlet.shared.models.explanations;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.shared.models.explanations.ExplanationQuestion;
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
import kotlinx.serialization.internal.C5053g;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.K;
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class ExplanationQuestion$$serializer implements D {

    @NotNull
    public static final ExplanationQuestion$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        ExplanationQuestion$$serializer explanationQuestion$$serializer = new ExplanationQuestion$$serializer();
        INSTANCE = explanationQuestion$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("ExplanationQuestion", explanationQuestion$$serializer, 9);
        pluginGeneratedSerialDescriptor.k("id", false);
        pluginGeneratedSerialDescriptor.k("questionUuid", false);
        pluginGeneratedSerialDescriptor.k("slug", false);
        pluginGeneratedSerialDescriptor.k("mediaExerciseId", false);
        pluginGeneratedSerialDescriptor.k("prompt", false);
        pluginGeneratedSerialDescriptor.k("answersCount", false);
        pluginGeneratedSerialDescriptor.k("subjects", false);
        pluginGeneratedSerialDescriptor.k("webUrl", false);
        pluginGeneratedSerialDescriptor.k("isDeleted", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private ExplanationQuestion$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = ExplanationQuestion.k;
        q0 q0Var = q0.a;
        return new KSerializer[]{P.a, q0Var, q0Var, q0Var, ExplanationQuestion$Prompt$$serializer.INSTANCE, R1.e(K.a), kSerializerArr[6], R1.e(q0Var), R1.e(C5053g.a)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public ExplanationQuestion deserialize(@NotNull Decoder decoder) {
        KSerializer[] kSerializerArr;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr2 = ExplanationQuestion.k;
        Integer num = null;
        long j = 0;
        List list = null;
        String str = null;
        Boolean bool = null;
        String strR = null;
        String strR2 = null;
        String strR3 = null;
        ExplanationQuestion.Prompt prompt = null;
        int i = 0;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    continue;
                case 0:
                    kSerializerArr = kSerializerArr2;
                    j = aVarC.j(descriptor2, 0);
                    i |= 1;
                    break;
                case 1:
                    kSerializerArr = kSerializerArr2;
                    strR = aVarC.r(descriptor2, 1);
                    i |= 2;
                    break;
                case 2:
                    kSerializerArr = kSerializerArr2;
                    strR2 = aVarC.r(descriptor2, 2);
                    i |= 4;
                    break;
                case 3:
                    kSerializerArr = kSerializerArr2;
                    strR3 = aVarC.r(descriptor2, 3);
                    i |= 8;
                    break;
                case 4:
                    kSerializerArr = kSerializerArr2;
                    prompt = (ExplanationQuestion.Prompt) aVarC.z(descriptor2, 4, ExplanationQuestion$Prompt$$serializer.INSTANCE, prompt);
                    i |= 16;
                    break;
                case 5:
                    kSerializerArr = kSerializerArr2;
                    num = (Integer) aVarC.v(descriptor2, 5, K.a, num);
                    i |= 32;
                    break;
                case 6:
                    kSerializerArr = kSerializerArr2;
                    list = (List) aVarC.z(descriptor2, 6, kSerializerArr[6], list);
                    i |= 64;
                    break;
                case 7:
                    kSerializerArr = kSerializerArr2;
                    str = (String) aVarC.v(descriptor2, 7, q0.a, str);
                    i |= 128;
                    break;
                case 8:
                    kSerializerArr = kSerializerArr2;
                    bool = (Boolean) aVarC.v(descriptor2, 8, C5053g.a, bool);
                    i |= 256;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
            kSerializerArr2 = kSerializerArr;
        }
        aVarC.b(descriptor2);
        return new ExplanationQuestion(i, j, strR, strR2, strR3, prompt, num, list, str, bool);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull ExplanationQuestion value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        bVarC.C(descriptor2, 0, value.b);
        bVarC.r(descriptor2, 1, value.c);
        bVarC.r(descriptor2, 2, value.d);
        bVarC.r(descriptor2, 3, value.e);
        bVarC.i(descriptor2, 4, ExplanationQuestion$Prompt$$serializer.INSTANCE, value.f);
        bVarC.s(descriptor2, 5, K.a, value.g);
        bVarC.i(descriptor2, 6, ExplanationQuestion.k[6], value.h);
        bVarC.s(descriptor2, 7, q0.a, value.i);
        boolean zD = bVarC.D(descriptor2);
        Boolean bool = value.j;
        if (zD || bool != null) {
            bVarC.s(descriptor2, 8, C5053g.a, bool);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
