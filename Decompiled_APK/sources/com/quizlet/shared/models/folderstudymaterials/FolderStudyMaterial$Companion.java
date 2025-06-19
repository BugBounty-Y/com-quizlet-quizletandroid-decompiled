package com.quizlet.shared.models.folderstudymaterials;

import java.lang.annotation.Annotation;
import kotlin.Metadata;
import kotlin.jvm.internal.K;
import kotlin.reflect.c;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.e;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class FolderStudyMaterial$Companion {
    public static final /* synthetic */ FolderStudyMaterial$Companion a = new FolderStudyMaterial$Companion();

    @NotNull
    public final KSerializer serializer() {
        return new e("FolderStudyMaterial", K.a(a.class), new c[]{K.a(FolderStudyMaterial$ExplanationQuestionMaterial.class), K.a(FolderStudyMaterial$FolderMaterial.class), K.a(FolderStudyMaterial$NoteMaterial.class), K.a(FolderStudyMaterial$SetMaterial.class), K.a(FolderStudyMaterial$TextbookExerciseMaterial.class), K.a(FolderStudyMaterial$TextbookMaterial.class)}, new KSerializer[]{FolderStudyMaterial$ExplanationQuestionMaterial$$serializer.INSTANCE, FolderStudyMaterial$FolderMaterial$$serializer.INSTANCE, FolderStudyMaterial$NoteMaterial$$serializer.INSTANCE, FolderStudyMaterial$SetMaterial$$serializer.INSTANCE, FolderStudyMaterial$TextbookExerciseMaterial$$serializer.INSTANCE, FolderStudyMaterial$TextbookMaterial$$serializer.INSTANCE}, new Annotation[0]);
    }
}
