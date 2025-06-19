package com.quizlet.remote.model.folderstudymaterial;

import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.quizlet.remote.model.folderstudymaterial.FolderStudyMaterialResponse;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements com.quizlet.remote.mapper.base.a {
    public final com.quizlet.quizletandroid.ui.login.di.a a;
    public final com.quizlet.data.repository.studysetwithcreatorinclass.g b;

    public c(com.quizlet.quizletandroid.ui.login.di.a folderStudyMaterialMapper, com.quizlet.data.repository.studysetwithcreatorinclass.g studyMaterialItemMapper) {
        Intrinsics.checkNotNullParameter(folderStudyMaterialMapper, "folderStudyMaterialMapper");
        Intrinsics.checkNotNullParameter(studyMaterialItemMapper, "studyMaterialItemMapper");
        this.a = folderStudyMaterialMapper;
        this.b = studyMaterialItemMapper;
    }

    @Override // com.quizlet.remote.mapper.base.a
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public final ArrayList c(FolderStudyMaterialResponse remote) {
        List list;
        List list2;
        List list3;
        List list4;
        List list5;
        List list6;
        List list7;
        List list8;
        Intrinsics.checkNotNullParameter(remote, "remote");
        FolderStudyMaterialResponse.Models models = remote.d;
        List listF = (models == null || (list8 = models.a) == null) ? K.a : S.f(this.a, list8);
        FolderStudyMaterialResponse.Models models2 = remote.d;
        if (models2 == null || (list = models2.b) == null) {
            list = K.a;
        }
        List list9 = list;
        if (models2 == null || (list2 = models2.d) == null) {
            list2 = K.a;
        }
        List list10 = list2;
        if (models2 == null || (list3 = models2.c) == null) {
            list3 = K.a;
        }
        List list11 = list3;
        if (models2 == null || (list4 = models2.f) == null) {
            list4 = K.a;
        }
        List list12 = list4;
        if (models2 == null || (list5 = models2.g) == null) {
            list5 = K.a;
        }
        List list13 = list5;
        if (models2 == null || (list6 = models2.e) == null) {
            list6 = K.a;
        }
        List list14 = list6;
        if (models2 == null || (list7 = models2.h) == null) {
            list7 = K.a;
        }
        return this.b.c(new com.quizlet.remote.model.studymaterial.a(listF, list9, list10, list11, list12, list13, list14, list7));
    }

    @Override // com.quizlet.remote.mapper.base.a
    public final List e(List list) {
        return S.f(this, list);
    }
}
