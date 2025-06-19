package com.quizlet.shared.models.api.notes;

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
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5053g;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class StudyNotesResponse$$serializer implements D {

    @NotNull
    public static final StudyNotesResponse$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        StudyNotesResponse$$serializer studyNotesResponse$$serializer = new StudyNotesResponse$$serializer();
        INSTANCE = studyNotesResponse$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.notes.StudyNotesResponse", studyNotesResponse$$serializer, 9);
        pluginGeneratedSerialDescriptor.k("uuid", false);
        pluginGeneratedSerialDescriptor.k("userId", false);
        pluginGeneratedSerialDescriptor.k("documentType", false);
        pluginGeneratedSerialDescriptor.k("private", false);
        pluginGeneratedSerialDescriptor.k("extractedText", false);
        pluginGeneratedSerialDescriptor.k("createdAt", false);
        pluginGeneratedSerialDescriptor.k("userModifiedAt", false);
        pluginGeneratedSerialDescriptor.k("artifacts", false);
        pluginGeneratedSerialDescriptor.k("redirectToWeb", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private StudyNotesResponse$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        KSerializer[] kSerializerArr = StudyNotesResponse.j;
        q0 q0Var = q0.a;
        C5053g c5053g = C5053g.a;
        return new KSerializer[]{q0Var, P.a, q0Var, c5053g, R1.e(q0Var), q0Var, R1.e(q0Var), kSerializerArr[7], R1.e(c5053g)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public StudyNotesResponse deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = StudyNotesResponse.j;
        String str = null;
        String strR = null;
        String strR2 = null;
        String str2 = null;
        String strR3 = null;
        long j = 0;
        boolean z = true;
        int i = 0;
        boolean zQ = false;
        List list = null;
        Boolean bool = null;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    z = false;
                    break;
                case 0:
                    strR = aVarC.r(descriptor2, 0);
                    i |= 1;
                    break;
                case 1:
                    j = aVarC.j(descriptor2, 1);
                    i |= 2;
                    break;
                case 2:
                    strR2 = aVarC.r(descriptor2, 2);
                    i |= 4;
                    break;
                case 3:
                    zQ = aVarC.q(descriptor2, 3);
                    i |= 8;
                    break;
                case 4:
                    str2 = (String) aVarC.v(descriptor2, 4, q0.a, str2);
                    i |= 16;
                    break;
                case 5:
                    strR3 = aVarC.r(descriptor2, 5);
                    i |= 32;
                    break;
                case 6:
                    str = (String) aVarC.v(descriptor2, 6, q0.a, str);
                    i |= 64;
                    break;
                case 7:
                    list = (List) aVarC.z(descriptor2, 7, kSerializerArr[7], list);
                    i |= 128;
                    break;
                case 8:
                    bool = (Boolean) aVarC.v(descriptor2, 8, C5053g.a, bool);
                    i |= 256;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new StudyNotesResponse(i, strR, j, strR2, zQ, str2, strR3, str, list, bool);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull StudyNotesResponse value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.r(descriptor2, 0, value.a);
        bVarC.C(descriptor2, 1, value.b);
        bVarC.r(descriptor2, 2, value.c);
        bVarC.p(descriptor2, 3, value.d);
        q0 q0Var = q0.a;
        bVarC.s(descriptor2, 4, q0Var, value.e);
        bVarC.r(descriptor2, 5, value.f);
        bVarC.s(descriptor2, 6, q0Var, value.g);
        bVarC.i(descriptor2, 7, StudyNotesResponse.j[7], value.h);
        boolean zD = bVarC.D(descriptor2);
        Boolean bool = value.i;
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
