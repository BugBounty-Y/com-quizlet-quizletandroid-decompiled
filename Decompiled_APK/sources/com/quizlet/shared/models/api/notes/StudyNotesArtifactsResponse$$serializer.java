package com.quizlet.shared.models.api.notes;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
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
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class StudyNotesArtifactsResponse$$serializer implements D {

    @NotNull
    public static final StudyNotesArtifactsResponse$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        StudyNotesArtifactsResponse$$serializer studyNotesArtifactsResponse$$serializer = new StudyNotesArtifactsResponse$$serializer();
        INSTANCE = studyNotesArtifactsResponse$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.notes.StudyNotesArtifactsResponse", studyNotesArtifactsResponse$$serializer, 9);
        pluginGeneratedSerialDescriptor.k("uuid", false);
        pluginGeneratedSerialDescriptor.k("noteUuid", false);
        pluginGeneratedSerialDescriptor.k("userId", false);
        pluginGeneratedSerialDescriptor.k(DBUserFields.Names.USER_UPGRADE_TYPE, false);
        pluginGeneratedSerialDescriptor.k("status", false);
        pluginGeneratedSerialDescriptor.k("content", false);
        pluginGeneratedSerialDescriptor.k("createdAt", false);
        pluginGeneratedSerialDescriptor.k("updatedAt", false);
        pluginGeneratedSerialDescriptor.k("history", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private StudyNotesArtifactsResponse$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        q0 q0Var = q0.a;
        return new KSerializer[]{q0Var, q0Var, P.a, q0Var, com.quizlet.shared.enums.studynotes.c.f, q0Var, q0Var, q0Var, R1.e(q0Var)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public StudyNotesArtifactsResponse deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        String str = null;
        int i = 0;
        String strR = null;
        String strR2 = null;
        String strR3 = null;
        com.quizlet.shared.enums.studynotes.d dVar = null;
        String strR4 = null;
        String strR5 = null;
        String strR6 = null;
        long j = 0;
        boolean z = true;
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
                    strR2 = aVarC.r(descriptor2, 1);
                    i |= 2;
                    break;
                case 2:
                    j = aVarC.j(descriptor2, 2);
                    i |= 4;
                    break;
                case 3:
                    strR3 = aVarC.r(descriptor2, 3);
                    i |= 8;
                    break;
                case 4:
                    dVar = (com.quizlet.shared.enums.studynotes.d) aVarC.z(descriptor2, 4, com.quizlet.shared.enums.studynotes.c.f, dVar);
                    i |= 16;
                    break;
                case 5:
                    strR4 = aVarC.r(descriptor2, 5);
                    i |= 32;
                    break;
                case 6:
                    strR5 = aVarC.r(descriptor2, 6);
                    i |= 64;
                    break;
                case 7:
                    strR6 = aVarC.r(descriptor2, 7);
                    i |= 128;
                    break;
                case 8:
                    str = (String) aVarC.v(descriptor2, 8, q0.a, str);
                    i |= 256;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new StudyNotesArtifactsResponse(i, strR, strR2, j, strR3, dVar, strR4, strR5, strR6, str);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull StudyNotesArtifactsResponse value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.r(descriptor2, 0, value.a);
        bVarC.r(descriptor2, 1, value.b);
        bVarC.C(descriptor2, 2, value.c);
        bVarC.r(descriptor2, 3, value.d);
        bVarC.i(descriptor2, 4, com.quizlet.shared.enums.studynotes.c.f, value.e);
        bVarC.r(descriptor2, 5, value.f);
        bVarC.r(descriptor2, 6, value.g);
        bVarC.r(descriptor2, 7, value.h);
        boolean zD = bVarC.D(descriptor2);
        String str = value.i;
        if (zD || str != null) {
            bVarC.s(descriptor2, 8, q0.a, str);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
