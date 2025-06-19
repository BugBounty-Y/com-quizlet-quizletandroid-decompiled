package com.quizlet.featuregate.injection;

import com.google.android.gms.internal.mlkit_common.u;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.google.firebase.crashlytics.internal.metadata.p;
import com.quizlet.data.model.C4184z;
import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.db.data.models.persisted.fields.DBImageRefFields;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.quizletandroid.R;
import com.quizlet.remote.model.explanations.search.RemoteSearchResultQuestion;
import com.quizlet.remote.model.explanations.search.b;
import com.quizlet.remote.model.explanations.textbook.RemoteTextbook;
import com.quizlet.remote.model.explanations.toc.RemoteChapter;
import com.quizlet.remote.model.explanations.toc.RemoteExerciseGroup;
import com.quizlet.remote.model.explanations.toc.RemoteSection;
import com.squareup.moshi.D;
import dagger.internal.c;
import io.reactivex.rxjava3.core.o;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.O;
import kotlinx.coroutines.scheduling.d;
import kotlinx.coroutines.scheduling.e;

/* loaded from: classes2.dex */
public abstract class a implements c {
    public static C4184z a() {
        C4184z c4184z = com.quizlet.quizletandroid.provider.a.a;
        S6.c(c4184z);
        return c4184z;
    }

    public static com.quizlet.shared.usecase.folderstudymaterials.a b() {
        return new com.quizlet.shared.usecase.folderstudymaterials.a(25);
    }

    public static com.quizlet.shared.usecase.folderstudymaterials.a c() {
        return new com.quizlet.shared.usecase.folderstudymaterials.a(25);
    }

    public static AbstractC5040y d() {
        e eVar = O.a;
        d dVar = d.b;
        S6.c(dVar);
        return dVar;
    }

    public static retrofit2.converter.moshi.a e() {
        p pVar = new p(1);
        List list = Collections.EMPTY_LIST;
        if (list.contains("textbook")) {
            throw new IllegalArgumentException("Labels must be unique.");
        }
        ArrayList arrayList = new ArrayList(list);
        arrayList.add("textbook");
        ArrayList arrayList2 = new ArrayList(list);
        arrayList2.add(RemoteTextbook.class);
        com.squareup.moshi.adapters.a aVarB = new com.squareup.moshi.adapters.a(b.class, DBImageRefFields.Names.MODEL_TYPE, arrayList, arrayList2).b(RemoteSearchResultQuestion.class, "question");
        Intrinsics.checkNotNullExpressionValue(aVarB, "withSubtype(...)");
        pVar.a(aVarB);
        if (list.contains("chapter")) {
            throw new IllegalArgumentException("Labels must be unique.");
        }
        ArrayList arrayList3 = new ArrayList(list);
        arrayList3.add("chapter");
        ArrayList arrayList4 = new ArrayList(list);
        arrayList4.add(RemoteChapter.class);
        com.squareup.moshi.adapters.a aVarB2 = new com.squareup.moshi.adapters.a(com.quizlet.remote.model.explanations.toc.a.class, DBUserFields.Names.USER_UPGRADE_TYPE, arrayList3, arrayList4).b(RemoteSection.class, "section").b(RemoteExerciseGroup.class, DBGroup.TABLE_NAME);
        Intrinsics.checkNotNullExpressionValue(aVarB2, "withSubtype(...)");
        pVar.a(aVarB2);
        pVar.a(new com.quizlet.remote.util.b(1));
        pVar.a(new com.quizlet.remote.model.selectedterm.c(0));
        pVar.a(new com.quizlet.remote.util.b(0));
        retrofit2.converter.moshi.a aVar = new retrofit2.converter.moshi.a(new D(pVar));
        Intrinsics.checkNotNullExpressionValue(aVar, "create(...)");
        return aVar;
    }

    public static List f() {
        List listJ = B.j(Integer.valueOf(R.string.setpage_ad_unit_AndroidSetSqr), Integer.valueOf(R.string.setpage_ad_unit_AndroidSetSqr2), Integer.valueOf(R.string.setpage_ad_unit_AndroidSetSqr3), Integer.valueOf(R.string.setpage_ad_unit_AndroidSetSqr4), Integer.valueOf(R.string.setpage_ad_unit_AndroidSetSqr5), Integer.valueOf(R.string.setpage_ad_unit_AndroidSetSqr6), Integer.valueOf(R.string.setpage_ad_unit_AndroidSetSqr7), Integer.valueOf(R.string.setpage_ad_unit_AndroidSetSqr8), Integer.valueOf(R.string.setpage_ad_unit_AndroidSetSqr9), Integer.valueOf(R.string.setpage_ad_unit_AndroidSetSqr10));
        S6.c(listJ);
        return listJ;
    }

    public static com.quizlet.featuregate.features.studymodes.learn.a g() {
        return new com.quizlet.featuregate.features.studymodes.learn.a(3);
    }

    public static com.quizlet.featuregate.features.home.a h() {
        return new com.quizlet.featuregate.features.home.a();
    }

    public static com.quizlet.shared.usecase.srs.a i() {
        return new com.quizlet.shared.usecase.srs.a(25);
    }

    public static o j() {
        o oVarA = io.reactivex.rxjava3.android.schedulers.b.a();
        Intrinsics.checkNotNullExpressionValue(oVarA, "mainThread(...)");
        return oVarA;
    }

    public static o k() {
        o oVar = io.reactivex.rxjava3.schedulers.e.b;
        Intrinsics.checkNotNullExpressionValue(oVar, "computation(...)");
        S6.c(oVar);
        return oVar;
    }

    public static o l() {
        o oVar = io.reactivex.rxjava3.schedulers.e.c;
        Intrinsics.checkNotNullExpressionValue(oVar, "io(...)");
        S6.c(oVar);
        return oVar;
    }

    public static u m() {
        return new u(26);
    }
}
