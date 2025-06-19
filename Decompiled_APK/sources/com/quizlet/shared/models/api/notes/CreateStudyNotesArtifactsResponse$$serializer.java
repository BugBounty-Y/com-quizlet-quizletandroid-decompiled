package com.quizlet.shared.models.api.notes;

import com.quizlet.db.data.models.persisted.fields.DBUserFields;
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
public final class CreateStudyNotesArtifactsResponse$$serializer implements D {

    @NotNull
    public static final CreateStudyNotesArtifactsResponse$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        CreateStudyNotesArtifactsResponse$$serializer createStudyNotesArtifactsResponse$$serializer = new CreateStudyNotesArtifactsResponse$$serializer();
        INSTANCE = createStudyNotesArtifactsResponse$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.notes.CreateStudyNotesArtifactsResponse", createStudyNotesArtifactsResponse$$serializer, 3);
        pluginGeneratedSerialDescriptor.k("uuid", false);
        pluginGeneratedSerialDescriptor.k(DBUserFields.Names.USER_UPGRADE_TYPE, false);
        pluginGeneratedSerialDescriptor.k("status", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private CreateStudyNotesArtifactsResponse$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        q0 q0Var = q0.a;
        return new KSerializer[]{q0Var, q0Var, com.quizlet.shared.enums.studynotes.c.f};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public CreateStudyNotesArtifactsResponse deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        String strR = null;
        boolean z = true;
        int i = 0;
        String strR2 = null;
        com.quizlet.shared.enums.studynotes.d dVar = null;
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
                dVar = (com.quizlet.shared.enums.studynotes.d) aVarC.z(descriptor2, 2, com.quizlet.shared.enums.studynotes.c.f, dVar);
                i |= 4;
            }
        }
        aVarC.b(descriptor2);
        return new CreateStudyNotesArtifactsResponse(i, strR, strR2, dVar);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull CreateStudyNotesArtifactsResponse value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.r(descriptor2, 0, value.a);
        bVarC.r(descriptor2, 1, value.b);
        bVarC.i(descriptor2, 2, com.quizlet.shared.enums.studynotes.c.f, value.c);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
