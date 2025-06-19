package com.quizlet.shared.models.api.notes;

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
public final class NotesEssayArtifactItemResponse$$serializer implements D {

    @NotNull
    public static final NotesEssayArtifactItemResponse$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        NotesEssayArtifactItemResponse$$serializer notesEssayArtifactItemResponse$$serializer = new NotesEssayArtifactItemResponse$$serializer();
        INSTANCE = notesEssayArtifactItemResponse$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("com.quizlet.shared.models.api.notes.NotesEssayArtifactItemResponse", notesEssayArtifactItemResponse$$serializer, 2);
        pluginGeneratedSerialDescriptor.k("difficulty", false);
        pluginGeneratedSerialDescriptor.k("prompt", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private NotesEssayArtifactItemResponse$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{com.quizlet.shared.enums.studynotes.a.f, q0.a};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public NotesEssayArtifactItemResponse deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        com.quizlet.shared.enums.studynotes.b bVar = null;
        boolean z = true;
        int i = 0;
        String strR = null;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                bVar = (com.quizlet.shared.enums.studynotes.b) aVarC.z(descriptor2, 0, com.quizlet.shared.enums.studynotes.a.f, bVar);
                i |= 1;
            } else {
                if (iT != 1) {
                    throw new UnknownFieldException(iT);
                }
                strR = aVarC.r(descriptor2, 1);
                i |= 2;
            }
        }
        aVarC.b(descriptor2);
        return new NotesEssayArtifactItemResponse(i, bVar, strR);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull NotesEssayArtifactItemResponse value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.i(descriptor2, 0, com.quizlet.shared.enums.studynotes.a.f, value.a);
        bVarC.r(descriptor2, 1, value.b);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
