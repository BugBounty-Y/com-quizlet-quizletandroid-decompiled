package com.quizlet.local.ormlite.models.studysetwithcreator;

import com.google.mlkit.vision.documentscanner.internal.c;
import com.quizlet.data.model.StudySet;
import com.quizlet.data.model.StudySetWithCreator;
import com.quizlet.data.model.User;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.single.g;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements com.quizlet.data.repository.base.a {
    public final com.quizlet.local.ormlite.models.bookmark.a a;
    public final com.quizlet.local.ormlite.models.bookmark.a b;

    public a(com.quizlet.local.ormlite.models.bookmark.a studySetLocal, com.quizlet.local.ormlite.models.bookmark.a userLocal) {
        Intrinsics.checkNotNullParameter(studySetLocal, "studySetLocal");
        Intrinsics.checkNotNullParameter(userLocal, "userLocal");
        this.a = studySetLocal;
        this.b = userLocal;
    }

    public static final ArrayList b(a aVar, List list, List list2) {
        aVar.getClass();
        ArrayList arrayListJ = CollectionsKt.J(list2);
        int iA = U.a(C.q(arrayListJ, 10));
        if (iA < 16) {
            iA = 16;
        }
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
        Iterator it2 = arrayListJ.iterator();
        while (it2.hasNext()) {
            Object next = it2.next();
            linkedHashMap.put(Long.valueOf(((User) next).a), next);
        }
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        Iterator it3 = list.iterator();
        while (it3.hasNext()) {
            StudySet studySet = (StudySet) it3.next();
            arrayList.add(new StudySetWithCreator(studySet, (User) linkedHashMap.get(Long.valueOf(studySet.e))));
        }
        return arrayList;
    }

    @Override // com.quizlet.data.repository.base.a
    public final p a(List models) {
        Intrinsics.checkNotNullParameter(models, "models");
        ArrayList arrayList = new ArrayList(C.q(models, 10));
        Iterator it2 = models.iterator();
        while (it2.hasNext()) {
            arrayList.add(((StudySetWithCreator) it2.next()).a);
        }
        ArrayList arrayList2 = new ArrayList();
        Iterator it3 = models.iterator();
        while (it3.hasNext()) {
            User user = ((StudySetWithCreator) it3.next()).b;
            if (user != null) {
                arrayList2.add(user);
            }
        }
        p pVarP = p.p(this.a.a(arrayList), this.b.a(arrayList2), new com.quizlet.data.interactor.course.a(this, 21));
        Intrinsics.checkNotNullExpressionValue(pVarP, "Single.zip(s1, s2, BiFun…-> zipper.invoke(t, u) })");
        return pVarP;
    }

    public final p c(List ids) {
        Intrinsics.checkNotNullParameter(ids, "ids");
        g gVarE = this.a.b(ids).e(new c(this, 28));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }
}
