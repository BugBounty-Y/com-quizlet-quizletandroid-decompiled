package com.quizlet.quizletandroid.ui.preview.dataclass;

import com.quizlet.data.model.StudySet;
import com.quizlet.data.model.Z1;
import com.quizlet.data.model.i2;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements io.reactivex.rxjava3.functions.b, h {
    public static final b a = new b();
    public static final b b = new b();

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        Object[] previews = (Object[]) obj;
        Intrinsics.checkNotNullParameter(previews, "previews");
        ArrayList arrayList = new ArrayList(previews.length);
        for (Object obj2 : previews) {
            Intrinsics.e(obj2, "null cannot be cast to non-null type com.quizlet.quizletandroid.ui.preview.dataclass.PreviewData");
            arrayList.add((a) obj2);
        }
        return arrayList;
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object obj, Object obj2) {
        Z1 studySetWithCreator = (Z1) obj;
        List<i2> terms = (List) obj2;
        Intrinsics.checkNotNullParameter(studySetWithCreator, "studySetWithCreator");
        Intrinsics.checkNotNullParameter(terms, "terms");
        StudySet studySet = studySetWithCreator.a;
        ArrayList arrayList = new ArrayList(C.q(terms, 10));
        for (i2 i2Var : terms) {
            arrayList.add(new c(i2Var.a, i2Var.e, i2Var.f, i2Var.g));
        }
        return new a(studySet.a, studySet.h, studySet.n, arrayList);
    }
}
