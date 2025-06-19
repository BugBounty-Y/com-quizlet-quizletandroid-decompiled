package com.quizlet.shared.models.notes;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.shared.enums.studynotes.d;
import com.quizlet.shared.enums.studynotes.e;
import com.quizlet.shared.enums.studynotes.f;
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
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.P;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class StudyNoteArtifactInfo$Flashcards$$serializer implements D {

    @NotNull
    public static final StudyNoteArtifactInfo$Flashcards$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        StudyNoteArtifactInfo$Flashcards$$serializer studyNoteArtifactInfo$Flashcards$$serializer = new StudyNoteArtifactInfo$Flashcards$$serializer();
        INSTANCE = studyNoteArtifactInfo$Flashcards$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("StudyNoteArtifactInfoFlashcards", studyNoteArtifactInfo$Flashcards$$serializer, 5);
        pluginGeneratedSerialDescriptor.k("uuid", false);
        pluginGeneratedSerialDescriptor.k("status", false);
        pluginGeneratedSerialDescriptor.k("setId", true);
        pluginGeneratedSerialDescriptor.k("cards", true);
        pluginGeneratedSerialDescriptor.k("studyNotesArtifactType", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private StudyNoteArtifactInfo$Flashcards$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{q0.a, com.quizlet.shared.enums.studynotes.c.f, R1.e(P.a), R1.e(StudyNoteArtifactInfo$Flashcards.h[3]), e.f};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public StudyNoteArtifactInfo$Flashcards deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = StudyNoteArtifactInfo$Flashcards.h;
        int i = 0;
        String strR = null;
        d dVar = null;
        Long l = null;
        List list = null;
        f fVar = null;
        boolean z = true;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                strR = aVarC.r(descriptor2, 0);
                i |= 1;
            } else if (iT == 1) {
                dVar = (d) aVarC.z(descriptor2, 1, com.quizlet.shared.enums.studynotes.c.f, dVar);
                i |= 2;
            } else if (iT == 2) {
                l = (Long) aVarC.v(descriptor2, 2, P.a, l);
                i |= 4;
            } else if (iT == 3) {
                list = (List) aVarC.v(descriptor2, 3, kSerializerArr[3], list);
                i |= 8;
            } else {
                if (iT != 4) {
                    throw new UnknownFieldException(iT);
                }
                fVar = (f) aVarC.z(descriptor2, 4, e.f, fVar);
                i |= 16;
            }
        }
        aVarC.b(descriptor2);
        return new StudyNoteArtifactInfo$Flashcards(i, strR, dVar, l, list, fVar);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull StudyNoteArtifactInfo$Flashcards value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.r(descriptor2, 0, value.c);
        bVarC.i(descriptor2, 1, com.quizlet.shared.enums.studynotes.c.f, value.d);
        boolean zD = bVarC.D(descriptor2);
        Long l = value.e;
        if (zD || l != null) {
            bVarC.s(descriptor2, 2, P.a, l);
        }
        boolean zD2 = bVarC.D(descriptor2);
        List list = value.f;
        if (zD2 || list != null) {
            bVarC.s(descriptor2, 3, StudyNoteArtifactInfo$Flashcards.h[3], list);
        }
        boolean zD3 = bVarC.D(descriptor2);
        f fVar = value.g;
        if (zD3 || fVar != f.e) {
            bVarC.i(descriptor2, 4, e.f, fVar);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
