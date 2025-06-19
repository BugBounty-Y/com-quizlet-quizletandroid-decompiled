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
public final class NewStudyNotesInfo$$serializer implements D {

    @NotNull
    public static final NewStudyNotesInfo$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        NewStudyNotesInfo$$serializer newStudyNotesInfo$$serializer = new NewStudyNotesInfo$$serializer();
        INSTANCE = newStudyNotesInfo$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("NewStudyNotesInfo", newStudyNotesInfo$$serializer, 13);
        pluginGeneratedSerialDescriptor.k("uuid", false);
        pluginGeneratedSerialDescriptor.k("userId", false);
        pluginGeneratedSerialDescriptor.k("title", false);
        pluginGeneratedSerialDescriptor.k("outlineMarkdown", false);
        pluginGeneratedSerialDescriptor.k("reviewSheet", false);
        pluginGeneratedSerialDescriptor.k("flashcards", false);
        pluginGeneratedSerialDescriptor.k("essay", false);
        pluginGeneratedSerialDescriptor.k("redirectToWeb", true);
        pluginGeneratedSerialDescriptor.k("documentType", true);
        pluginGeneratedSerialDescriptor.k("isPrivate", true);
        pluginGeneratedSerialDescriptor.k("extractedText", true);
        pluginGeneratedSerialDescriptor.k("createdAt", true);
        pluginGeneratedSerialDescriptor.k("userModifiedAt", true);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private NewStudyNotesInfo$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        q0 q0Var = q0.a;
        C5053g c5053g = C5053g.a;
        return new KSerializer[]{q0Var, P.a, StudyNoteArtifactInfo$Title$$serializer.INSTANCE, StudyNoteArtifactInfo$OutlineMarkdown$$serializer.INSTANCE, StudyNoteArtifactInfo$ReviewSheet$$serializer.INSTANCE, StudyNoteArtifactInfo$Flashcards$$serializer.INSTANCE, StudyNoteArtifactInfo$EssayPrompts$$serializer.INSTANCE, c5053g, R1.e(q0Var), R1.e(c5053g), R1.e(q0Var), R1.e(q0Var), R1.e(q0Var)};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public NewStudyNotesInfo deserialize(@NotNull Decoder decoder) {
        String str;
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        StudyNoteArtifactInfo$EssayPrompts studyNoteArtifactInfo$EssayPrompts = null;
        String str2 = null;
        String str3 = null;
        String strR = null;
        String str4 = null;
        StudyNoteArtifactInfo$Title studyNoteArtifactInfo$Title = null;
        StudyNoteArtifactInfo$OutlineMarkdown studyNoteArtifactInfo$OutlineMarkdown = null;
        StudyNoteArtifactInfo$ReviewSheet studyNoteArtifactInfo$ReviewSheet = null;
        StudyNoteArtifactInfo$Flashcards studyNoteArtifactInfo$Flashcards = null;
        long j = 0;
        int i = 0;
        boolean z = true;
        boolean zQ = false;
        String str5 = null;
        Boolean bool = null;
        while (z) {
            int iT = aVarC.t(descriptor2);
            switch (iT) {
                case -1:
                    str = strR;
                    z = false;
                    break;
                case 0:
                    i |= 1;
                    strR = aVarC.r(descriptor2, 0);
                    continue;
                case 1:
                    j = aVarC.j(descriptor2, 1);
                    i |= 2;
                    continue;
                case 2:
                    str = strR;
                    studyNoteArtifactInfo$Title = (StudyNoteArtifactInfo$Title) aVarC.z(descriptor2, 2, StudyNoteArtifactInfo$Title$$serializer.INSTANCE, studyNoteArtifactInfo$Title);
                    i |= 4;
                    break;
                case 3:
                    str = strR;
                    studyNoteArtifactInfo$OutlineMarkdown = (StudyNoteArtifactInfo$OutlineMarkdown) aVarC.z(descriptor2, 3, StudyNoteArtifactInfo$OutlineMarkdown$$serializer.INSTANCE, studyNoteArtifactInfo$OutlineMarkdown);
                    i |= 8;
                    break;
                case 4:
                    str = strR;
                    studyNoteArtifactInfo$ReviewSheet = (StudyNoteArtifactInfo$ReviewSheet) aVarC.z(descriptor2, 4, StudyNoteArtifactInfo$ReviewSheet$$serializer.INSTANCE, studyNoteArtifactInfo$ReviewSheet);
                    i |= 16;
                    break;
                case 5:
                    str = strR;
                    studyNoteArtifactInfo$Flashcards = (StudyNoteArtifactInfo$Flashcards) aVarC.z(descriptor2, 5, StudyNoteArtifactInfo$Flashcards$$serializer.INSTANCE, studyNoteArtifactInfo$Flashcards);
                    i |= 32;
                    break;
                case 6:
                    str = strR;
                    studyNoteArtifactInfo$EssayPrompts = (StudyNoteArtifactInfo$EssayPrompts) aVarC.z(descriptor2, 6, StudyNoteArtifactInfo$EssayPrompts$$serializer.INSTANCE, studyNoteArtifactInfo$EssayPrompts);
                    i |= 64;
                    break;
                case 7:
                    zQ = aVarC.q(descriptor2, 7);
                    i |= 128;
                    continue;
                case 8:
                    str = strR;
                    str5 = (String) aVarC.v(descriptor2, 8, q0.a, str5);
                    i |= 256;
                    break;
                case 9:
                    str = strR;
                    bool = (Boolean) aVarC.v(descriptor2, 9, C5053g.a, bool);
                    i |= g.MAX_CONTENT_URL_LENGTH;
                    break;
                case 10:
                    str = strR;
                    str2 = (String) aVarC.v(descriptor2, 10, q0.a, str2);
                    i |= 1024;
                    break;
                case 11:
                    str = strR;
                    str3 = (String) aVarC.v(descriptor2, 11, q0.a, str3);
                    i |= 2048;
                    break;
                case 12:
                    str = strR;
                    str4 = (String) aVarC.v(descriptor2, 12, q0.a, str4);
                    i |= 4096;
                    break;
                default:
                    throw new UnknownFieldException(iT);
            }
            strR = str;
        }
        aVarC.b(descriptor2);
        return new NewStudyNotesInfo(i, strR, j, studyNoteArtifactInfo$Title, studyNoteArtifactInfo$OutlineMarkdown, studyNoteArtifactInfo$ReviewSheet, studyNoteArtifactInfo$Flashcards, studyNoteArtifactInfo$EssayPrompts, zQ, str5, bool, str2, str3, str4);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull NewStudyNotesInfo value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.r(descriptor2, 0, value.b);
        bVarC.C(descriptor2, 1, value.c);
        bVarC.i(descriptor2, 2, StudyNoteArtifactInfo$Title$$serializer.INSTANCE, value.d);
        bVarC.i(descriptor2, 3, StudyNoteArtifactInfo$OutlineMarkdown$$serializer.INSTANCE, value.e);
        bVarC.i(descriptor2, 4, StudyNoteArtifactInfo$ReviewSheet$$serializer.INSTANCE, value.f);
        bVarC.i(descriptor2, 5, StudyNoteArtifactInfo$Flashcards$$serializer.INSTANCE, value.g);
        bVarC.i(descriptor2, 6, StudyNoteArtifactInfo$EssayPrompts$$serializer.INSTANCE, value.h);
        boolean zD = bVarC.D(descriptor2);
        boolean z = value.i;
        if (zD || z) {
            bVarC.p(descriptor2, 7, z);
        }
        boolean zD2 = bVarC.D(descriptor2);
        String str = value.j;
        if (zD2 || str != null) {
            bVarC.s(descriptor2, 8, q0.a, str);
        }
        boolean zD3 = bVarC.D(descriptor2);
        Boolean bool = value.k;
        if (zD3 || bool != null) {
            bVarC.s(descriptor2, 9, C5053g.a, bool);
        }
        boolean zD4 = bVarC.D(descriptor2);
        String str2 = value.l;
        if (zD4 || str2 != null) {
            bVarC.s(descriptor2, 10, q0.a, str2);
        }
        boolean zD5 = bVarC.D(descriptor2);
        String str3 = value.m;
        if (zD5 || str3 != null) {
            bVarC.s(descriptor2, 11, q0.a, str3);
        }
        boolean zD6 = bVarC.D(descriptor2);
        String str4 = value.n;
        if (zD6 || str4 != null) {
            bVarC.s(descriptor2, 12, q0.a, str4);
        }
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
