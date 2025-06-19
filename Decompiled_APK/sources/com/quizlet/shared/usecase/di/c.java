package com.quizlet.shared.usecase.di;

import androidx.compose.ui.node.B;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3410x2;
import com.quizlet.shared.usecase.studiableMetadata.h;
import com.quizlet.shared.usecase.studynotes.j;
import com.quizlet.shared.usecase.studynotes.l;
import com.quizlet.shared.usecase.studynotes.n;
import com.quizlet.shared.usecase.studynotes.q;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.r;
import org.koin.core.error.NoBeanDefFoundException;

/* loaded from: classes3.dex */
public final class c extends r implements Function2 {
    public static final c b = new c(2, 0);
    public static final c c = new c(2, 1);
    public static final c d = new c(2, 2);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) throws NoBeanDefFoundException {
        switch (this.a) {
            case 0:
                org.koin.core.scope.a factory = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it2 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(factory, "$this$factory");
                Intrinsics.checkNotNullParameter(it2, "it");
                return new n((com.quizlet.shared.repository.studynotes.c) factory.a(null, K.a(com.quizlet.shared.repository.studynotes.c.class), null), (q) factory.a(null, K.a(q.class), null));
            case 1:
                org.koin.core.scope.a factory2 = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it3 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(factory2, "$this$factory");
                Intrinsics.checkNotNullParameter(it3, "it");
                return new com.quizlet.shared.usecase.session.b((com.quizlet.shared.cache.a) factory2.a(null, K.a(com.quizlet.shared.cache.a.class), AbstractC3410x2.b("persistent")), (com.quizlet.shared.cache.a) factory2.a(null, K.a(com.quizlet.shared.cache.a.class), AbstractC3410x2.b("inMemory")));
            case 2:
                org.koin.core.scope.a factory3 = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it4 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(factory3, "$this$factory");
                Intrinsics.checkNotNullParameter(it4, "it");
                return new com.quizlet.shared.usecase.session.c((com.quizlet.shared.cache.a) factory3.a(null, K.a(com.quizlet.shared.cache.a.class), AbstractC3410x2.b("inMemory")));
            case 3:
                org.koin.core.scope.a aVar = (org.koin.core.scope.a) obj;
                return new com.quizlet.shared.usecase.grading.b((com.quizlet.shared.repository.a) aVar.a(null, B.q(aVar, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.shared.repository.a.class), null));
            case 4:
                org.koin.core.scope.a aVar2 = (org.koin.core.scope.a) obj;
                com.quizlet.shared.usecase.studiableMetadata.g getMultipleStudiableMetadataForSetUseCase = (com.quizlet.shared.usecase.studiableMetadata.g) aVar2.a(null, B.q(aVar2, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.shared.usecase.studiableMetadata.g.class), null);
                Intrinsics.checkNotNullParameter(getMultipleStudiableMetadataForSetUseCase, "getMultipleStudiableMetadataForSetUseCase");
                return new com.quizlet.shared.usecase.studiableMetadata.a(0);
            case 5:
                org.koin.core.scope.a aVar3 = (org.koin.core.scope.a) obj;
                return new com.quizlet.shared.usecase.studiableMetadata.d((h) aVar3.a(null, B.q(aVar3, "$this$factory", (org.koin.core.parameter.a) obj2, "it", h.class), null));
            case 6:
                org.koin.core.scope.a aVar4 = (org.koin.core.scope.a) obj;
                return new com.quizlet.shared.usecase.studiableMetadata.f((com.quizlet.shared.repository.c) aVar4.a(null, B.q(aVar4, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.shared.repository.c.class), null));
            case 7:
                org.koin.core.scope.a aVar5 = (org.koin.core.scope.a) obj;
                com.quizlet.shared.repository.b repository = (com.quizlet.shared.repository.b) aVar5.a(null, B.q(aVar5, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.shared.repository.b.class), null);
                Intrinsics.checkNotNullParameter(repository, "repository");
                return new com.quizlet.shared.usecase.srs.a(0);
            case 8:
                org.koin.core.scope.a aVar6 = (org.koin.core.scope.a) obj;
                return new com.quizlet.shared.usecase.eligibility.b((com.quizlet.shared.repository.eligibility.a) aVar6.a(null, B.q(aVar6, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.shared.repository.eligibility.a.class), null));
            case 9:
                org.koin.core.scope.a aVar7 = (org.koin.core.scope.a) obj;
                com.quizlet.shared.repository.folderstudymaterials.f deleteFolderStudyMaterialsRepository = (com.quizlet.shared.repository.folderstudymaterials.f) aVar7.a(null, B.q(aVar7, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.shared.repository.folderstudymaterials.f.class), null);
                Intrinsics.checkNotNullParameter(deleteFolderStudyMaterialsRepository, "deleteFolderStudyMaterialsRepository");
                return new com.quizlet.shared.usecase.folderstudymaterials.b(0);
            case 10:
                org.koin.core.scope.a aVar8 = (org.koin.core.scope.a) obj;
                return new com.quizlet.shared.usecase.studynotes.h((com.quizlet.shared.repository.studynotes.d) aVar8.a(null, B.q(aVar8, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.shared.repository.studynotes.d.class), null), (q) aVar8.a(null, K.a(q.class), null));
            case 11:
                org.koin.core.scope.a aVar9 = (org.koin.core.scope.a) obj;
                return new com.quizlet.shared.usecase.studynotes.f((com.quizlet.shared.repository.d) aVar9.a(null, B.q(aVar9, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.shared.repository.d.class), null), (kotlinx.serialization.json.c) aVar9.a(null, K.a(kotlinx.serialization.json.c.class), null));
            case 12:
                org.koin.core.scope.a aVar10 = (org.koin.core.scope.a) obj;
                return new l((com.quizlet.shared.repository.studynotes.e) aVar10.a(null, B.q(aVar10, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.shared.repository.studynotes.e.class), null), (q) aVar10.a(null, K.a(q.class), null));
            case 13:
                org.koin.core.scope.a aVar11 = (org.koin.core.scope.a) obj;
                return new j((com.quizlet.shared.repository.studynotes.e) aVar11.a(null, B.q(aVar11, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.shared.repository.studynotes.e.class), null), (q) aVar11.a(null, K.a(q.class), null));
            case 14:
                org.koin.core.scope.a aVar12 = (org.koin.core.scope.a) obj;
                return new com.quizlet.shared.usecase.studynotes.b((com.quizlet.shared.repository.studynotes.b) aVar12.a(null, B.q(aVar12, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.shared.repository.studynotes.b.class), null), (n) aVar12.a(null, K.a(n.class), null));
            case 15:
                org.koin.core.scope.a aVar13 = (org.koin.core.scope.a) obj;
                return new com.quizlet.shared.usecase.studynotes.d((com.quizlet.shared.repository.studynotes.b) aVar13.a(null, B.q(aVar13, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.shared.repository.studynotes.b.class), null), (n) aVar13.a(null, K.a(n.class), null));
            case 16:
                org.koin.core.scope.a aVar14 = (org.koin.core.scope.a) obj;
                com.quizlet.shared.repository.folderstudymaterials.c folderStudyMaterialsRepository = (com.quizlet.shared.repository.folderstudymaterials.c) aVar14.a(null, B.q(aVar14, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.shared.repository.folderstudymaterials.c.class), null);
                Intrinsics.checkNotNullParameter(folderStudyMaterialsRepository, "folderStudyMaterialsRepository");
                return new com.quizlet.shared.usecase.folderstudymaterials.c(0);
            case 17:
                org.koin.core.scope.a aVar15 = (org.koin.core.scope.a) obj;
                Object objA = aVar15.a(null, B.q(aVar15, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.shared.repository.folders.a.class), null);
                com.quizlet.shared.repository.folderstudymaterials.b folderStudyMaterialsFolderIdsRepository = (com.quizlet.shared.repository.folderstudymaterials.b) aVar15.a(null, K.a(com.quizlet.shared.repository.folderstudymaterials.b.class), null);
                com.quizlet.shared.repository.folders.a foldersRepository = (com.quizlet.shared.repository.folders.a) objA;
                Intrinsics.checkNotNullParameter(foldersRepository, "foldersRepository");
                Intrinsics.checkNotNullParameter(folderStudyMaterialsFolderIdsRepository, "folderStudyMaterialsFolderIdsRepository");
                return new com.quizlet.shared.usecase.folderstudymaterials.d(0);
            default:
                org.koin.core.scope.a aVar16 = (org.koin.core.scope.a) obj;
                com.quizlet.shared.repository.folderstudymaterials.f createFolderStudyMaterialsRepository = (com.quizlet.shared.repository.folderstudymaterials.f) aVar16.a(null, B.q(aVar16, "$this$factory", (org.koin.core.parameter.a) obj2, "it", com.quizlet.shared.repository.folderstudymaterials.f.class), null);
                Intrinsics.checkNotNullParameter(createFolderStudyMaterialsRepository, "createFolderStudyMaterialsRepository");
                return new com.quizlet.shared.usecase.folderstudymaterials.a(0);
        }
    }
}
