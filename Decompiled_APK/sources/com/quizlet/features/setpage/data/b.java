package com.quizlet.features.setpage.data;

import com.google.android.gms.internal.mlkit_vision_document_scanner.J6;
import com.quizlet.data.model.W1;
import com.quizlet.data.model.Z1;
import com.quizlet.features.setpage.state.d;
import com.quizlet.quizletandroid.R;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.functions.i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements i, h {
    public static final b a = new b();
    public static final b b = new b();
    public static final b c = new b();

    public static int a(com.quizlet.featuregate.contracts.enums.a alternateStudyModeNamesType) {
        Intrinsics.checkNotNullParameter(alternateStudyModeNamesType, "alternateStudyModeNamesType");
        int iOrdinal = alternateStudyModeNamesType.ordinal();
        return iOrdinal != 1 ? iOrdinal != 2 ? iOrdinal != 3 ? iOrdinal != 4 ? R.string.learn : R.string.learn_copy_pt_br_estude : R.string.learn_copy_pt_br_treine : R.string.learn_copy_pt_br_aprenda : R.string.learn_es_mx_alternate;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        d it2 = (d) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        J6 j6 = ((Z1) ((com.quizlet.features.setpage.state.c) it2).a).c;
        Intrinsics.e(j6, "null cannot be cast to non-null type com.quizlet.data.model.StudySetClassificationData.Valid");
        return (W1) j6;
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        d it2 = (d) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        return (it2 instanceof com.quizlet.features.setpage.state.c) && (((Z1) ((com.quizlet.features.setpage.state.c) it2).a).c instanceof W1);
    }
}
