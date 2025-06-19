package com.quizlet.features.folders.viewmodel.usecases;

import androidx.compose.foundation.lazy.layout.C0429a;
import com.quizlet.generated.enums.y1;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k {
    public static final ArrayList c;
    public final com.quizlet.data.interactor.folderstudymaterial.o a;
    public final C0429a b;

    static {
        kotlin.enums.a aVarA = y1.a();
        ArrayList arrayList = new ArrayList();
        for (Object obj : aVarA) {
            if (((y1) obj) != y1.FOLDER) {
                arrayList.add(obj);
            }
        }
        c = arrayList;
    }

    public k(com.quizlet.data.interactor.folderstudymaterial.o studyMaterialsUseCase, C0429a folderStudyMaterialMapper) {
        Intrinsics.checkNotNullParameter(studyMaterialsUseCase, "studyMaterialsUseCase");
        Intrinsics.checkNotNullParameter(folderStudyMaterialMapper, "folderStudyMaterialMapper");
        this.a = studyMaterialsUseCase;
        this.b = folderStudyMaterialMapper;
    }
}
