package com.quizlet.shared.models.notes;

import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.quizlet.shared.enums.studynotes.d;
import com.quizlet.shared.enums.studynotes.e;
import com.quizlet.shared.enums.studynotes.f;
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
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes3.dex */
public final class StudyNoteArtifactInfo$OutlineMarkdown$$serializer implements D {

    @NotNull
    public static final StudyNoteArtifactInfo$OutlineMarkdown$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        StudyNoteArtifactInfo$OutlineMarkdown$$serializer studyNoteArtifactInfo$OutlineMarkdown$$serializer = new StudyNoteArtifactInfo$OutlineMarkdown$$serializer();
        INSTANCE = studyNoteArtifactInfo$OutlineMarkdown$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("StudyNoteArtifactInfoOutlineMarkdown", studyNoteArtifactInfo$OutlineMarkdown$$serializer, 5);
        pluginGeneratedSerialDescriptor.k("uuid", false);
        pluginGeneratedSerialDescriptor.k("status", false);
        pluginGeneratedSerialDescriptor.k("outline", true);
        pluginGeneratedSerialDescriptor.k("editedByCreator", true);
        pluginGeneratedSerialDescriptor.k("studyNotesArtifactType", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private StudyNoteArtifactInfo$OutlineMarkdown$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        q0 q0Var = q0.a;
        return new KSerializer[]{q0Var, com.quizlet.shared.enums.studynotes.c.f, R1.e(q0Var), C5053g.a, e.f};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public StudyNoteArtifactInfo$OutlineMarkdown deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        int i = 0;
        boolean zQ = false;
        String strR = null;
        d dVar = null;
        String str = null;
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
                str = (String) aVarC.v(descriptor2, 2, q0.a, str);
                i |= 4;
            } else if (iT == 3) {
                zQ = aVarC.q(descriptor2, 3);
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
        return new StudyNoteArtifactInfo$OutlineMarkdown(i, strR, dVar, str, zQ, fVar);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull StudyNoteArtifactInfo$OutlineMarkdown value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.r(descriptor2, 0, value.c);
        bVarC.i(descriptor2, 1, com.quizlet.shared.enums.studynotes.c.f, value.d);
        boolean zD = bVarC.D(descriptor2);
        String str = value.e;
        if (zD || str != null) {
            bVarC.s(descriptor2, 2, q0.a, str);
        }
        boolean zD2 = bVarC.D(descriptor2);
        boolean z = value.f;
        if (zD2 || z) {
            bVarC.p(descriptor2, 3, z);
        }
        boolean zD3 = bVarC.D(descriptor2);
        f fVar = value.g;
        if (zD3 || fVar != f.d) {
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
