package com.quizlet.remote.model.folder.course;

import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.zxing.aztec.encoder.c;
import com.quizlet.data.model.C4168t1;
import com.quizlet.data.repository.studysetwithcreatorinclass.g;
import com.quizlet.remote.model.folder.course.CourseStudyMaterialRecommendationsResponse;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements com.quizlet.remote.mapper.base.a {
    public final b a;
    public final g b;

    public a(b recommendedStudyMaterialModelMapper, g studyMaterialItemMapper) {
        Intrinsics.checkNotNullParameter(recommendedStudyMaterialModelMapper, "recommendedStudyMaterialModelMapper");
        Intrinsics.checkNotNullParameter(studyMaterialItemMapper, "studyMaterialItemMapper");
        this.a = recommendedStudyMaterialModelMapper;
        this.b = studyMaterialItemMapper;
    }

    public final ArrayList a(CourseStudyMaterialRecommendationsResponse remote) {
        List list;
        List list2;
        List list3;
        List list4;
        List list5;
        List list6;
        List list7;
        List list8;
        Intrinsics.checkNotNullParameter(remote, "remote");
        CourseStudyMaterialRecommendationsResponse.Models models = remote.d;
        if (models == null || (list = models.a) == null) {
            list = K.a;
        }
        List listN0 = CollectionsKt.n0(S.f(this.a, list), new c(23));
        CourseStudyMaterialRecommendationsResponse.Models models2 = remote.d;
        if (models2 == null || (list2 = models2.g) == null) {
            list2 = K.a;
        }
        List list9 = list2;
        if (models2 == null || (list3 = models2.d) == null) {
            list3 = K.a;
        }
        List list10 = list3;
        if (models2 == null || (list4 = models2.b) == null) {
            list4 = K.a;
        }
        List list11 = list4;
        if (models2 == null || (list5 = models2.e) == null) {
            list5 = K.a;
        }
        List list12 = list5;
        if (models2 == null || (list6 = models2.f) == null) {
            list6 = K.a;
        }
        List list13 = list6;
        if (models2 == null || (list7 = models2.h) == null) {
            list7 = K.a;
        }
        List list14 = list7;
        if (models2 == null || (list8 = models2.c) == null) {
            list8 = K.a;
        }
        ArrayList studyMaterials = this.b.c(new com.quizlet.remote.model.studymaterial.a(listN0, list9, list10, list11, list12, list13, list14, list8));
        Intrinsics.checkNotNullParameter(studyMaterials, "studyMaterials");
        return studyMaterials;
    }

    @Override // com.quizlet.remote.mapper.base.a
    public final /* synthetic */ Object c(Object obj) {
        return new C4168t1(a((CourseStudyMaterialRecommendationsResponse) obj));
    }

    @Override // com.quizlet.remote.mapper.base.a
    public final List e(List list) {
        return S.f(this, list);
    }
}
