package com.quizlet.shared.repository;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3410x2;
import com.google.android.gms.internal.mlkit_vision_camera.Z2;
import com.quizlet.shared.cache.u;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.r;
import kotlinx.coroutines.O;

/* loaded from: classes3.dex */
public final class e extends r implements Function2 {
    public static final e b = new e(2, 0);
    public static final e c = new e(2, 1);
    public static final e d = new e(2, 2);
    public static final e e = new e(2, 3);
    public static final e f = new e(2, 4);
    public static final e g = new e(2, 5);
    public static final e h = new e(2, 6);
    public static final e i = new e(2, 7);
    public static final e j = new e(2, 8);
    public static final e k = new e(2, 9);
    public static final e l = new e(2, 10);
    public static final e m = new e(2, 11);
    public static final e n = new e(2, 12);
    public static final e o = new e(2, 13);
    public static final e p = new e(2, 14);
    public static final e q = new e(2, 15);
    public static final e r = new e(2, 16);
    public static final e s = new e(2, 17);
    public static final e t = new e(2, 18);
    public static final e u = new e(2, 19);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ e(int i2, int i3) {
        super(i2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                org.koin.core.scope.a factory = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it2 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(factory, "$this$factory");
                Intrinsics.checkNotNullParameter(it2, "it");
                com.quizlet.shared.cache.a cache = (com.quizlet.shared.cache.a) factory.a(null, K.a(com.quizlet.shared.repository.folders.d.class), null);
                com.quizlet.shared.quizletapi.base.d service = (com.quizlet.shared.quizletapi.base.d) factory.a(null, K.a(com.quizlet.shared.quizletapi.folders.b.class), null);
                com.quizlet.shared.mapper.a mapper = (com.quizlet.shared.mapper.a) factory.a(null, K.a(com.quizlet.shared.repository.folders.g.class), null);
                kotlinx.coroutines.scheduling.e dispatcher = O.a;
                Intrinsics.checkNotNullParameter(service, "service");
                Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
                Intrinsics.checkNotNullParameter(mapper, "mapper");
                com.quizlet.quizletandroid.ui.joincontenttofolder.j delegate = new com.quizlet.quizletandroid.ui.joincontenttofolder.j(4);
                Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
                Intrinsics.checkNotNullParameter(cache, "cache");
                Intrinsics.checkNotNullParameter(delegate, "delegate");
                com.quizlet.quizletandroid.ui.login.di.a readRepository = new com.quizlet.quizletandroid.ui.login.di.a(4);
                Intrinsics.checkNotNullParameter(readRepository, "readRepository");
                return new com.quizlet.shared.repository.folders.a();
            case 1:
                org.koin.core.scope.a factory2 = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it3 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(factory2, "$this$factory");
                Intrinsics.checkNotNullParameter(it3, "it");
                com.quizlet.shared.quizletapi.base.e service2 = (com.quizlet.shared.quizletapi.base.e) factory2.a(null, K.a(com.quizlet.shared.quizletapi.folderstudymaterials.b.class), null);
                kotlinx.coroutines.scheduling.e dispatcher2 = O.a;
                com.quizlet.shared.mapper.a mapper2 = (com.quizlet.shared.mapper.a) factory2.a(null, K.a(com.quizlet.shared.repository.folderstudymaterials.e.class), null);
                Intrinsics.checkNotNullParameter(service2, "service");
                Intrinsics.checkNotNullParameter(dispatcher2, "dispatcher");
                Intrinsics.checkNotNullParameter(mapper2, "mapper");
                com.quizlet.quizletandroid.ui.onboarding.a readRepository2 = new com.quizlet.quizletandroid.ui.onboarding.a(4);
                Intrinsics.checkNotNullParameter(readRepository2, "readRepository");
                return new com.quizlet.shared.repository.folderstudymaterials.c();
            case 2:
                org.koin.core.scope.a factory3 = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it4 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(factory3, "$this$factory");
                Intrinsics.checkNotNullParameter(it4, "it");
                com.quizlet.shared.quizletapi.base.e service3 = (com.quizlet.shared.quizletapi.base.e) factory3.a(null, K.a(com.quizlet.shared.quizletapi.folderstudymaterials.b.class), null);
                kotlinx.coroutines.scheduling.e dispatcher3 = O.a;
                Intrinsics.checkNotNullParameter(service3, "service");
                Intrinsics.checkNotNullParameter(dispatcher3, "dispatcher");
                return new com.quizlet.shared.repository.folderstudymaterials.b();
            case 3:
                org.koin.core.scope.a factory4 = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it5 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(factory4, "$this$factory");
                Intrinsics.checkNotNullParameter(it5, "it");
                com.quizlet.shared.quizletapi.base.e service4 = (com.quizlet.shared.quizletapi.base.e) factory4.a(null, K.a(com.quizlet.shared.quizletapi.folderstudymaterials.c.class), null);
                kotlinx.coroutines.scheduling.e dispatcher4 = O.a;
                com.quizlet.shared.mapper.a mapper3 = (com.quizlet.shared.mapper.a) factory4.a(null, K.a(com.quizlet.shared.repository.folderstudymaterials.d.class), null);
                Intrinsics.checkNotNullParameter(service4, "service");
                Intrinsics.checkNotNullParameter(dispatcher4, "dispatcher");
                Intrinsics.checkNotNullParameter(mapper3, "mapper");
                com.quizlet.quizletandroid.ui.profile.b writeRepository = new com.quizlet.quizletandroid.ui.profile.b();
                Intrinsics.checkNotNullParameter(writeRepository, "writeRepository");
                return new com.quizlet.shared.repository.folderstudymaterials.f();
            case 4:
                org.koin.core.scope.a factory5 = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it6 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(factory5, "$this$factory");
                Intrinsics.checkNotNullParameter(it6, "it");
                com.quizlet.shared.mapper.a titleArtifactMapper = (com.quizlet.shared.mapper.a) factory5.a(null, K.a(com.quizlet.shared.repository.studynotes.f.class), null);
                Intrinsics.checkNotNullParameter(titleArtifactMapper, "titleArtifactMapper");
                return new com.quizlet.shared.repository.studynotes.g();
            case 5:
                org.koin.core.parameter.a it7 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter((org.koin.core.scope.a) obj, "$this$factory");
                Intrinsics.checkNotNullParameter(it7, "it");
                return new com.quizlet.shared.repository.studynotes.h();
            case 6:
                org.koin.core.scope.a factory6 = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it8 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(factory6, "$this$factory");
                Intrinsics.checkNotNullParameter(it8, "it");
                com.quizlet.shared.mapper.a explanationQuestionMapper = (com.quizlet.shared.mapper.a) factory6.a(null, K.a(com.quizlet.shared.repository.explanations.explanationquestions.a.class), null);
                com.quizlet.shared.mapper.a folderMapper = (com.quizlet.shared.mapper.a) factory6.a(null, K.a(com.quizlet.shared.repository.folders.e.class), null);
                com.quizlet.shared.mapper.a studySetMapper = (com.quizlet.shared.mapper.a) factory6.a(null, K.a(com.quizlet.shared.repository.studyset.a.class), null);
                com.quizlet.shared.mapper.a textbookExerciseMapper = (com.quizlet.shared.mapper.a) factory6.a(null, K.a(com.quizlet.shared.repository.explanations.textbookexercises.a.class), null);
                com.quizlet.shared.mapper.a textbookMapper = (com.quizlet.shared.mapper.a) factory6.a(null, K.a(com.quizlet.shared.repository.explanations.textbooks.a.class), null);
                com.quizlet.shared.mapper.a studyNoteMapper = (com.quizlet.shared.mapper.a) factory6.a(null, K.a(com.quizlet.shared.repository.studynotes.h.class), null);
                com.quizlet.shared.mapper.a userMapper = (com.quizlet.shared.mapper.a) factory6.a(null, K.a(com.quizlet.shared.repository.user.a.class), null);
                Intrinsics.checkNotNullParameter(explanationQuestionMapper, "explanationQuestionMapper");
                Intrinsics.checkNotNullParameter(folderMapper, "folderMapper");
                Intrinsics.checkNotNullParameter(studySetMapper, "studySetMapper");
                Intrinsics.checkNotNullParameter(textbookExerciseMapper, "textbookExerciseMapper");
                Intrinsics.checkNotNullParameter(textbookMapper, "textbookMapper");
                Intrinsics.checkNotNullParameter(studyNoteMapper, "studyNoteMapper");
                Intrinsics.checkNotNullParameter(userMapper, "userMapper");
                return new com.quizlet.shared.repository.folderstudymaterials.e();
            case 7:
                org.koin.core.parameter.a it9 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter((org.koin.core.scope.a) obj, "$this$factory");
                Intrinsics.checkNotNullParameter(it9, "it");
                return new com.quizlet.shared.repository.folderstudymaterials.d();
            case 8:
                org.koin.core.parameter.a it10 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter((org.koin.core.scope.a) obj, "$this$factory");
                Intrinsics.checkNotNullParameter(it10, "it");
                return new com.quizlet.shared.repository.user.a();
            case 9:
                org.koin.core.scope.a factory7 = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it11 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(factory7, "$this$factory");
                Intrinsics.checkNotNullParameter(it11, "it");
                com.quizlet.shared.mapper.a remoteUserToUser = (com.quizlet.shared.mapper.a) factory7.a(null, K.a(com.quizlet.shared.repository.user.a.class), null);
                Intrinsics.checkNotNullParameter(remoteUserToUser, "remoteUserToUser");
                return new com.quizlet.shared.repository.folders.e();
            case 10:
                org.koin.core.scope.a factory8 = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it12 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(factory8, "$this$factory");
                Intrinsics.checkNotNullParameter(it12, "it");
                com.quizlet.shared.mapper.a remoteFolderToFolderModel = (com.quizlet.shared.mapper.a) factory8.a(null, K.a(com.quizlet.shared.repository.folders.e.class), null);
                Intrinsics.checkNotNullParameter(remoteFolderToFolderModel, "remoteFolderToFolderModel");
                return new com.quizlet.shared.repository.folders.f();
            case 11:
                org.koin.core.scope.a factory9 = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it13 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(factory9, "$this$factory");
                Intrinsics.checkNotNullParameter(it13, "it");
                com.quizlet.shared.mapper.a remoteFolderToFolderModel2 = (com.quizlet.shared.mapper.a) factory9.a(null, K.a(com.quizlet.shared.repository.folders.f.class), null);
                Intrinsics.checkNotNullParameter(remoteFolderToFolderModel2, "remoteFolderToFolderModel");
                return new com.quizlet.shared.repository.folders.g();
            case 12:
                org.koin.core.scope.a factory10 = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it14 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(factory10, "$this$factory");
                Intrinsics.checkNotNullParameter(it14, "it");
                com.quizlet.shared.mapper.a remoteUserToUser2 = (com.quizlet.shared.mapper.a) factory10.a(null, K.a(com.quizlet.shared.repository.user.a.class), null);
                Intrinsics.checkNotNullParameter(remoteUserToUser2, "remoteUserToUser");
                return new com.quizlet.shared.repository.studyset.a();
            case 13:
                org.koin.core.parameter.a it15 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter((org.koin.core.scope.a) obj, "$this$factory");
                Intrinsics.checkNotNullParameter(it15, "it");
                return new com.quizlet.shared.repository.explanations.explanationquestions.b();
            case 14:
                org.koin.core.parameter.a it16 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter((org.koin.core.scope.a) obj, "$this$factory");
                Intrinsics.checkNotNullParameter(it16, "it");
                return new com.quizlet.shared.repository.explanations.textbooks.a();
            case 15:
                org.koin.core.scope.a factory11 = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it17 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(factory11, "$this$factory");
                Intrinsics.checkNotNullParameter(it17, "it");
                com.quizlet.shared.mapper.a textbookMapper2 = (com.quizlet.shared.mapper.a) factory11.a(null, K.a(com.quizlet.shared.repository.explanations.textbooks.a.class), null);
                Intrinsics.checkNotNullParameter(textbookMapper2, "textbookMapper");
                return new com.quizlet.shared.repository.explanations.textbookexercises.a();
            case 16:
                org.koin.core.scope.a factory12 = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it18 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(factory12, "$this$factory");
                Intrinsics.checkNotNullParameter(it18, "it");
                kotlinx.serialization.json.c json = (kotlinx.serialization.json.c) factory12.a(null, K.a(kotlinx.serialization.json.c.class), AbstractC3410x2.b("data-layer-json"));
                Intrinsics.checkNotNullParameter(json, "json");
                return new com.quizlet.shared.repository.studynotes.f();
            case 17:
                org.koin.core.scope.a factory13 = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it19 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(factory13, "$this$factory");
                Intrinsics.checkNotNullParameter(it19, "it");
                return new com.quizlet.shared.repository.folders.d((com.quizlet.shared.cache.a) factory13.a(null, K.a(com.quizlet.shared.cache.a.class), AbstractC3410x2.b("persistent")), O.a);
            case 18:
                org.koin.core.scope.a factory14 = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it20 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(factory14, "$this$factory");
                Intrinsics.checkNotNullParameter(it20, "it");
                return new com.quizlet.shared.repository.folderstudymaterials.a((com.quizlet.shared.cache.a) factory14.a(null, K.a(com.quizlet.shared.cache.a.class), AbstractC3410x2.b("persistent")));
            default:
                org.koin.core.parameter.a it21 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter((org.koin.core.scope.a) obj, "$this$factory");
                Intrinsics.checkNotNullParameter(it21, "it");
                return Z2.b(kotlinx.serialization.modules.f.a(kotlinx.serialization.modules.f.a(com.quizlet.shared.models.api.a.b.b, com.quizlet.shared.models.a.a.b), u.a.b));
        }
    }
}
