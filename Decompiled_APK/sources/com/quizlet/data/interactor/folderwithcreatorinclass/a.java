package com.quizlet.data.interactor.folderwithcreatorinclass;

import com.quizlet.data.model.C4117c2;
import com.quizlet.data.model.ContentFolder;
import com.quizlet.data.model.F;
import com.quizlet.data.model.G;
import com.quizlet.data.model.StudySetWithCreator;
import com.quizlet.data.repository.folderwithcreator.e;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a implements h {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ List b;

    public a(e eVar, List list) {
        this.b = list;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                Map studySetCountMap = (Map) obj;
                Intrinsics.checkNotNullParameter(studySetCountMap, "studySetCountMap");
                List<G> list = this.b;
                Intrinsics.d(list);
                if (studySetCountMap.isEmpty()) {
                    return list;
                }
                ArrayList arrayList = new ArrayList(C.q(list, 10));
                for (G g : list) {
                    ContentFolder contentFolder = g.a;
                    Integer num = contentFolder.x;
                    Integer num2 = (Integer) studySetCountMap.get(Long.valueOf(contentFolder.l));
                    if (num2 != null || num == null) {
                        ContentFolder folder = ContentFolder.l(g.a, 0L, null, Integer.valueOf(num2 != null ? num2.intValue() : 0), 28671);
                        Intrinsics.checkNotNullParameter(folder, "folder");
                        g = new G(folder, g.b, g.c, g.d);
                    }
                    arrayList.add(g);
                }
                return arrayList;
            default:
                List list2 = (List) obj;
                ArrayList arrayListM = assistantMode.refactored.a.m("studySetsWithCreator", list2);
                for (Object obj2 : this.b) {
                    F f = (F) obj2;
                    if (!Intrinsics.b(f.h, Boolean.TRUE) && !f.k) {
                        arrayListM.add(obj2);
                    }
                }
                StudySetWithCreator studySetWithCreator = (StudySetWithCreator) CollectionsKt.firstOrNull(list2);
                if (studySetWithCreator == null) {
                    return K.a;
                }
                ArrayList arrayList2 = new ArrayList(C.q(arrayListM, 10));
                Iterator it2 = arrayListM.iterator();
                while (it2.hasNext()) {
                    F f2 = (F) it2.next();
                    arrayList2.add(new C4117c2(studySetWithCreator.a, studySetWithCreator.b, f2.g, f2.f, Long.valueOf(f2.b)));
                }
                return arrayList2;
        }
    }

    public a(List list) {
        this.b = list;
    }
}
