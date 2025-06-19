package com.quizlet.shared.models.api.explanations;

import com.google.android.gms.ads.g;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.shared.models.api.explanations.RemoteExplanationQuestion;
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
public final class RemoteExplanationQuestion$$serializer implements D {

    @NotNull
    public static final RemoteExplanationQuestion$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        RemoteExplanationQuestion$$serializer remoteExplanationQuestion$$serializer = new RemoteExplanationQuestion$$serializer();
        INSTANCE = remoteExplanationQuestion$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.explanations.RemoteExplanationQuestion", remoteExplanationQuestion$$serializer, 11);
        pluginGeneratedSerialDescriptor.k("id", false);
        pluginGeneratedSerialDescriptor.k("questionUuid", false);
        pluginGeneratedSerialDescriptor.k("slug", false);
        pluginGeneratedSerialDescriptor.k("mediaExerciseId", false);
        pluginGeneratedSerialDescriptor.k("prompt", false);
        pluginGeneratedSerialDescriptor.k("answersCount", false);
        pluginGeneratedSerialDescriptor.k("subjectIds", false);
        pluginGeneratedSerialDescriptor.k("_webUrl", false);
        pluginGeneratedSerialDescriptor.k("timestamp", false);
        pluginGeneratedSerialDescriptor.k("lastModified", false);
        pluginGeneratedSerialDescriptor.k("isDeleted", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private RemoteExplanationQuestion$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = RemoteExplanationQuestion.l;
        P p = P.a;
        KSerializer kSerializerE = R1.e(p);
        q0 q0Var = q0.a;
        return new KSerializer[]{kSerializerE, R1.e(q0Var), R1.e(q0Var), R1.e(q0Var), R1.e(RemoteExplanationQuestion$Prompt$$serializer.INSTANCE), R1.e(K.a), R1.e(kSerializerArr[6]), R1.e(q0Var), R1.e(p), R1.e(p), R1.e(C5053g.a)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public RemoteExplanationQuestion deserialize(@NotNull Decoder decoder) {
        KSerializer[] kSerializerArr;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr2 = RemoteExplanationQuestion.l;
        Long l = null;
        Long l2 = null;
        Boolean bool = null;
        Long l3 = null;
        String str = null;
        String str2 = null;
        String str3 = null;
        RemoteExplanationQuestion.Prompt prompt = null;
        Integer num = null;
        List list = null;
        String str4 = null;
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
                    l3 = (Long) aVarC.v(descriptor2, 0, P.a, l3);
                    i |= 1;
                    break;
                case 1:
                    kSerializerArr = kSerializerArr2;
                    str = (String) aVarC.v(descriptor2, 1, q0.a, str);
                    i |= 2;
                    break;
                case 2:
                    kSerializerArr = kSerializerArr2;
                    str2 = (String) aVarC.v(descriptor2, 2, q0.a, str2);
                    i |= 4;
                    break;
                case 3:
                    kSerializerArr = kSerializerArr2;
                    str3 = (String) aVarC.v(descriptor2, 3, q0.a, str3);
                    i |= 8;
                    break;
                case 4:
                    kSerializerArr = kSerializerArr2;
                    prompt = (RemoteExplanationQuestion.Prompt) aVarC.v(descriptor2, 4, RemoteExplanationQuestion$Prompt$$serializer.INSTANCE, prompt);
                    i |= 16;
                    break;
                case 5:
                    kSerializerArr = kSerializerArr2;
                    num = (Integer) aVarC.v(descriptor2, 5, K.a, num);
                    i |= 32;
                    break;
                case 6:
                    kSerializerArr = kSerializerArr2;
                    list = (List) aVarC.v(descriptor2, 6, kSerializerArr[6], list);
                    i |= 64;
                    break;
                case 7:
                    kSerializerArr = kSerializerArr2;
                    str4 = (String) aVarC.v(descriptor2, 7, q0.a, str4);
                    i |= 128;
                    break;
                case 8:
                    kSerializerArr = kSerializerArr2;
                    l = (Long) aVarC.v(descriptor2, 8, P.a, l);
                    i |= 256;
                    break;
                case 9:
                    kSerializerArr = kSerializerArr2;
                    l2 = (Long) aVarC.v(descriptor2, 9, P.a, l2);
                    i |= g.MAX_CONTENT_URL_LENGTH;
                    break;
                case 10:
                    kSerializerArr = kSerializerArr2;
                    bool = (Boolean) aVarC.v(descriptor2, 10, C5053g.a, bool);
                    i |= 1024;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
            kSerializerArr2 = kSerializerArr;
        }
        aVarC.b(descriptor2);
        return new RemoteExplanationQuestion(i, l3, str, str2, str3, prompt, num, list, str4, l, l2, bool);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull RemoteExplanationQuestion value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        b bVarC = encoder.c(descriptor2);
        RemoteExplanationQuestion.Companion companion = RemoteExplanationQuestion.Companion;
        P p = P.a;
        bVarC.s(descriptor2, 0, p, value.a);
        q0 q0Var = q0.a;
        bVarC.s(descriptor2, 1, q0Var, value.b);
        bVarC.s(descriptor2, 2, q0Var, value.c);
        bVarC.s(descriptor2, 3, q0Var, value.d);
        bVarC.s(descriptor2, 4, RemoteExplanationQuestion$Prompt$$serializer.INSTANCE, value.e);
        bVarC.s(descriptor2, 5, K.a, value.f);
        bVarC.s(descriptor2, 6, RemoteExplanationQuestion.l[6], value.g);
        bVarC.s(descriptor2, 7, q0Var, value.h);
        bVarC.s(descriptor2, 8, p, value.i);
        bVarC.s(descriptor2, 9, p, value.j);
        boolean zD = bVarC.D(descriptor2);
        Boolean bool = value.k;
        if (zD || bool != null) {
            bVarC.s(descriptor2, 10, C5053g.a, bool);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
