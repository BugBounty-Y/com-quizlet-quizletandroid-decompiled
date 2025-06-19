package com.quizlet.shared.models.notes;

import com.google.android.gms.ads.g;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
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
public final class FullStudyNotesInfo$$serializer implements D {

    @NotNull
    public static final FullStudyNotesInfo$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        FullStudyNotesInfo$$serializer fullStudyNotesInfo$$serializer = new FullStudyNotesInfo$$serializer();
        INSTANCE = fullStudyNotesInfo$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("FullStudyNotesInfo", fullStudyNotesInfo$$serializer, 13);
        pluginGeneratedSerialDescriptor.k("uuid", false);
        pluginGeneratedSerialDescriptor.k("userId", false);
        pluginGeneratedSerialDescriptor.k("documentType", false);
        pluginGeneratedSerialDescriptor.k("isPrivate", false);
        pluginGeneratedSerialDescriptor.k("extractedText", false);
        pluginGeneratedSerialDescriptor.k("createdAt", false);
        pluginGeneratedSerialDescriptor.k("title", false);
        pluginGeneratedSerialDescriptor.k("outlineMarkdown", false);
        pluginGeneratedSerialDescriptor.k("reviewSheet", false);
        pluginGeneratedSerialDescriptor.k("flashcards", false);
        pluginGeneratedSerialDescriptor.k("essay", false);
        pluginGeneratedSerialDescriptor.k("userModifiedAt", false);
        pluginGeneratedSerialDescriptor.k("redirectToWeb", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private FullStudyNotesInfo$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        q0 q0Var = q0.a;
        KSerializer kSerializerE = R1.e(StudyNoteArtifactInfo$Title$$serializer.INSTANCE);
        KSerializer kSerializerE2 = R1.e(StudyNoteArtifactInfo$OutlineMarkdown$$serializer.INSTANCE);
        KSerializer kSerializerE3 = R1.e(StudyNoteArtifactInfo$ReviewSheet$$serializer.INSTANCE);
        KSerializer kSerializerE4 = R1.e(StudyNoteArtifactInfo$Flashcards$$serializer.INSTANCE);
        KSerializer kSerializerE5 = R1.e(StudyNoteArtifactInfo$EssayPrompts$$serializer.INSTANCE);
        KSerializer kSerializerE6 = R1.e(q0Var);
        C5053g c5053g = C5053g.a;
        return new KSerializer[]{q0Var, P.a, q0Var, c5053g, q0Var, q0Var, kSerializerE, kSerializerE2, kSerializerE3, kSerializerE4, kSerializerE5, kSerializerE6, c5053g};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public FullStudyNotesInfo deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        StudyNoteArtifactInfo$Title studyNoteArtifactInfo$Title = null;
        StudyNoteArtifactInfo$Flashcards studyNoteArtifactInfo$Flashcards = null;
        StudyNoteArtifactInfo$EssayPrompts studyNoteArtifactInfo$EssayPrompts = null;
        String strR = null;
        String str = null;
        String strR2 = null;
        String strR3 = null;
        String strR4 = null;
        long j = 0;
        boolean z = true;
        int i = 0;
        boolean zQ = false;
        boolean zQ2 = false;
        StudyNoteArtifactInfo$OutlineMarkdown studyNoteArtifactInfo$OutlineMarkdown = null;
        StudyNoteArtifactInfo$ReviewSheet studyNoteArtifactInfo$ReviewSheet = null;
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
                    strR3 = aVarC.r(descriptor2, 4);
                    i |= 16;
                    break;
                case 5:
                    strR4 = aVarC.r(descriptor2, 5);
                    i |= 32;
                    break;
                case 6:
                    studyNoteArtifactInfo$Title = (StudyNoteArtifactInfo$Title) aVarC.v(descriptor2, 6, StudyNoteArtifactInfo$Title$$serializer.INSTANCE, studyNoteArtifactInfo$Title);
                    i |= 64;
                    break;
                case 7:
                    studyNoteArtifactInfo$OutlineMarkdown = (StudyNoteArtifactInfo$OutlineMarkdown) aVarC.v(descriptor2, 7, StudyNoteArtifactInfo$OutlineMarkdown$$serializer.INSTANCE, studyNoteArtifactInfo$OutlineMarkdown);
                    i |= 128;
                    break;
                case 8:
                    studyNoteArtifactInfo$ReviewSheet = (StudyNoteArtifactInfo$ReviewSheet) aVarC.v(descriptor2, 8, StudyNoteArtifactInfo$ReviewSheet$$serializer.INSTANCE, studyNoteArtifactInfo$ReviewSheet);
                    i |= 256;
                    break;
                case 9:
                    studyNoteArtifactInfo$Flashcards = (StudyNoteArtifactInfo$Flashcards) aVarC.v(descriptor2, 9, StudyNoteArtifactInfo$Flashcards$$serializer.INSTANCE, studyNoteArtifactInfo$Flashcards);
                    i |= g.MAX_CONTENT_URL_LENGTH;
                    break;
                case 10:
                    studyNoteArtifactInfo$EssayPrompts = (StudyNoteArtifactInfo$EssayPrompts) aVarC.v(descriptor2, 10, StudyNoteArtifactInfo$EssayPrompts$$serializer.INSTANCE, studyNoteArtifactInfo$EssayPrompts);
                    i |= 1024;
                    break;
                case 11:
                    str = (String) aVarC.v(descriptor2, 11, q0.a, str);
                    i |= 2048;
                    break;
                case 12:
                    zQ2 = aVarC.q(descriptor2, 12);
                    i |= 4096;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
        }
        aVarC.b(descriptor2);
        return new FullStudyNotesInfo(i, strR, j, strR2, zQ, strR3, strR4, studyNoteArtifactInfo$Title, studyNoteArtifactInfo$OutlineMarkdown, studyNoteArtifactInfo$ReviewSheet, studyNoteArtifactInfo$Flashcards, studyNoteArtifactInfo$EssayPrompts, str, zQ2);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull FullStudyNotesInfo value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.r(descriptor2, 0, value.b);
        bVarC.C(descriptor2, 1, value.c);
        bVarC.r(descriptor2, 2, value.d);
        bVarC.p(descriptor2, 3, value.e);
        bVarC.r(descriptor2, 4, value.f);
        bVarC.r(descriptor2, 5, value.g);
        bVarC.s(descriptor2, 6, StudyNoteArtifactInfo$Title$$serializer.INSTANCE, value.h);
        bVarC.s(descriptor2, 7, StudyNoteArtifactInfo$OutlineMarkdown$$serializer.INSTANCE, value.i);
        bVarC.s(descriptor2, 8, StudyNoteArtifactInfo$ReviewSheet$$serializer.INSTANCE, value.j);
        bVarC.s(descriptor2, 9, StudyNoteArtifactInfo$Flashcards$$serializer.INSTANCE, value.k);
        bVarC.s(descriptor2, 10, StudyNoteArtifactInfo$EssayPrompts$$serializer.INSTANCE, value.l);
        bVarC.s(descriptor2, 11, q0.a, value.m);
        boolean zD = bVarC.D(descriptor2);
        boolean z = value.n;
        if (zD || z) {
            bVarC.p(descriptor2, 12, z);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
