package com.quizlet.shared.models.api;

import androidx.camera.camera2.internal.p0;
import androidx.compose.animation.T;
import assistantMode.refactored.interfaces.c;
import assistantMode.refactored.modelTypes.AudioValue;
import assistantMode.refactored.modelTypes.DiagramShapeValue;
import assistantMode.refactored.modelTypes.ImageValue;
import assistantMode.refactored.modelTypes.McqAnswer;
import assistantMode.refactored.modelTypes.NSidedCardAnswer;
import assistantMode.refactored.modelTypes.TextValue;
import assistantMode.refactored.modelTypes.VideoValue;
import assistantMode.refactored.types.AlternativeQuestion;
import assistantMode.refactored.types.FillInTheBlankMultipleChoiceQuestionStudiableMetadata;
import assistantMode.refactored.types.MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata;
import assistantMode.refactored.types.f;
import assistantMode.types.unions.AudioAttribute;
import assistantMode.types.unions.ImageAttribute;
import assistantMode.types.unions.LocationAttribute;
import assistantMode.types.unions.TextAttribute;
import assistantMode.types.unions.VideoAttribute;
import com.google.android.gms.internal.mlkit_vision_camera.R1;
import com.google.android.gms.internal.mlkit_vision_camera.Y1;
import com.quizlet.remote.model.union.folderwithcreator.b;
import com.quizlet.shared.models.api.folders.GetFoldersById;
import com.quizlet.shared.models.api.folders.GetFoldersByUserIds;
import com.quizlet.shared.models.api.folderstudymaterials.CreateFolderStudyMaterialsRequest;
import com.quizlet.shared.models.api.folderstudymaterials.DeleteFolderStudyMaterialsRequest;
import com.quizlet.shared.models.api.folderstudymaterials.GetFolderStudyMaterialsByFolderId;
import com.quizlet.shared.models.api.folderstudymaterials.GetFolderStudyMaterialsByFolderIdAndType;
import com.quizlet.shared.models.api.folderstudymaterials.GetFolderStudyMaterialsByStudyMaterialIdAndType;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.N;
import kotlinx.serialization.internal.q0;
import kotlinx.serialization.json.q;
import serialization.e;

/* loaded from: classes3.dex */
public abstract class a {
    public static final p0 a;
    public static final q b;

    static {
        p0 p0Var = new p0();
        b bVar = new b(K.a(f.class));
        bVar.c(K.a(AlternativeQuestion.class), AlternativeQuestion.Companion.serializer());
        bVar.c(K.a(MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata.class), MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata.Companion.serializer());
        bVar.c(K.a(FillInTheBlankMultipleChoiceQuestionStudiableMetadata.class), FillInTheBlankMultipleChoiceQuestionStudiableMetadata.Companion.serializer());
        bVar.b(p0Var);
        b bVar2 = new b(K.a(assistantMode.types.unions.a.class));
        bVar2.c(K.a(TextAttribute.class), TextAttribute.Companion.serializer());
        bVar2.c(K.a(LocationAttribute.class), LocationAttribute.Companion.serializer());
        bVar2.c(K.a(ImageAttribute.class), ImageAttribute.Companion.serializer());
        bVar2.c(K.a(AudioAttribute.class), AudioAttribute.Companion.serializer());
        bVar2.c(K.a(VideoAttribute.class), VideoAttribute.Companion.serializer());
        bVar2.b(p0Var);
        b bVar3 = new b(K.a(c.class));
        bVar3.c(K.a(McqAnswer.class), McqAnswer.Companion.serializer());
        bVar3.c(K.a(NSidedCardAnswer.class), NSidedCardAnswer.Companion.serializer());
        bVar3.b(p0Var);
        b bVar4 = new b(K.a(assistantMode.refactored.modelTypes.c.class));
        bVar4.c(K.a(TextValue.class), TextValue.Companion.serializer());
        bVar4.c(K.a(ImageValue.class), ImageValue.Companion.serializer());
        bVar4.c(K.a(DiagramShapeValue.class), DiagramShapeValue.Companion.serializer());
        bVar4.c(K.a(AudioValue.class), AudioValue.Companion.serializer());
        bVar4.c(K.a(VideoValue.class), VideoValue.Companion.serializer());
        bVar4.b(p0Var);
        b bVar5 = new b(K.a(e.class));
        bVar5.c(K.a(GetFoldersById.class), GetFoldersById.Companion.serializer());
        bVar5.c(K.a(GetFoldersByUserIds.class), GetFoldersByUserIds.Companion.serializer());
        bVar5.c(K.a(CreateFolderStudyMaterialsRequest.class), CreateFolderStudyMaterialsRequest.Companion.serializer());
        bVar5.c(K.a(DeleteFolderStudyMaterialsRequest.class), DeleteFolderStudyMaterialsRequest.Companion.serializer());
        bVar5.c(K.a(GetFolderStudyMaterialsByFolderId.class), GetFolderStudyMaterialsByFolderId.Companion.serializer());
        bVar5.c(K.a(GetFolderStudyMaterialsByFolderIdAndType.class), GetFolderStudyMaterialsByFolderIdAndType.Companion.serializer());
        bVar5.c(K.a(GetFolderStudyMaterialsByStudyMaterialIdAndType.class), GetFolderStudyMaterialsByStudyMaterialIdAndType.Companion.serializer());
        bVar5.b(p0Var);
        R1.g(N.a);
        q0 q0Var = q0.a;
        p0Var.a(K.a(String.class));
        p0 p0VarG = p0Var.g();
        a = p0VarG;
        b = Y1.c(new T(p0VarG, false));
    }
}
