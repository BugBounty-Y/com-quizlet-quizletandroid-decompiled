package com.quizlet.shared.models.folderstudymaterials;

import java.lang.annotation.Annotation;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.reflect.c;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import org.jetbrains.annotations.NotNull;
import serialization.e;

@f
@Metadata
/* loaded from: classes3.dex */
public final class FolderStudyMaterials extends e {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] c = {new C5048d(new kotlinx.serialization.e("FolderStudyMaterial", K.a(a.class), new c[]{K.a(FolderStudyMaterial$ExplanationQuestionMaterial.class), K.a(FolderStudyMaterial$FolderMaterial.class), K.a(FolderStudyMaterial$NoteMaterial.class), K.a(FolderStudyMaterial$SetMaterial.class), K.a(FolderStudyMaterial$TextbookExerciseMaterial.class), K.a(FolderStudyMaterial$TextbookMaterial.class)}, new KSerializer[]{FolderStudyMaterial$ExplanationQuestionMaterial$$serializer.INSTANCE, FolderStudyMaterial$FolderMaterial$$serializer.INSTANCE, FolderStudyMaterial$NoteMaterial$$serializer.INSTANCE, FolderStudyMaterial$SetMaterial$$serializer.INSTANCE, FolderStudyMaterial$TextbookExerciseMaterial$$serializer.INSTANCE, FolderStudyMaterial$TextbookMaterial$$serializer.INSTANCE}, new Annotation[0]), 0)};
    public final List b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FolderStudyMaterials$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ FolderStudyMaterials(int i, List list) {
        if (1 == (i & 1)) {
            this.b = list;
        } else {
            AbstractC5047c0.k(i, 1, FolderStudyMaterials$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof FolderStudyMaterials) && Intrinsics.b(this.b, ((FolderStudyMaterials) obj).b);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("FolderStudyMaterials(folderStudyMaterials="), this.b);
    }
}
