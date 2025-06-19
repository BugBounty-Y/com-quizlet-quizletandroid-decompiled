package com.quizlet.data.repository.studysetwithcreatorinclass;

import com.quizlet.data.model.C4117c2;
import com.quizlet.data.model.F;
import com.quizlet.data.model.StudySetWithCreator;
import com.quizlet.data.model.User;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.collections.C;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class f implements h, io.reactivex.rxjava3.functions.b {
    public static final f b = new f(0);
    public static final f c = new f(1);
    public final /* synthetic */ int a;

    public /* synthetic */ f(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object t, Object u) {
        Intrinsics.checkNotNullExpressionValue(t, "t");
        Intrinsics.checkNotNullExpressionValue(u, "u");
        List list = (List) u;
        List list2 = (List) t;
        Intrinsics.d(list2);
        Intrinsics.d(list);
        return new a(list2, list);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 0:
                a remoteData = (a) obj;
                Intrinsics.checkNotNullParameter(remoteData, "remoteData");
                List list = remoteData.a;
                ArrayList arrayList = new ArrayList();
                for (Object obj2 : list) {
                    if (!Intrinsics.b(((F) obj2).h, Boolean.TRUE)) {
                        arrayList.add(obj2);
                    }
                }
                int iA = U.a(C.q(arrayList, 10));
                if (iA < 16) {
                    iA = 16;
                }
                LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    Object next = it2.next();
                    linkedHashMap.put(Long.valueOf(((F) next).c), next);
                }
                ArrayList arrayList2 = new ArrayList();
                for (Object obj3 : remoteData.b) {
                    if (!((StudySetWithCreator) obj3).a.y) {
                        arrayList2.add(obj3);
                    }
                }
                ArrayList arrayList3 = new ArrayList();
                Iterator it3 = arrayList2.iterator();
                while (it3.hasNext()) {
                    StudySetWithCreator studySetWithCreator = (StudySetWithCreator) it3.next();
                    F f = (F) linkedHashMap.get(Long.valueOf(studySetWithCreator.a.a));
                    C4117c2 c4117c2 = null;
                    if (f != null) {
                        User user = studySetWithCreator.b;
                        if (user != 0) {
                            Intrinsics.checkNotNullParameter(user, "<this>");
                            if (!user.l) {
                                c4117c2 = user;
                            }
                        }
                        c4117c2 = new C4117c2(studySetWithCreator.a, c4117c2, f.g, f.f, null);
                    }
                    if (c4117c2 != null) {
                        arrayList3.add(c4117c2);
                    }
                }
                return arrayList3;
            default:
                a remoteData2 = (a) obj;
                Intrinsics.checkNotNullParameter(remoteData2, "remoteData");
                LinkedHashMap linkedHashMap2 = new LinkedHashMap();
                List list2 = remoteData2.b;
                int iA2 = U.a(C.q(list2, 10));
                if (iA2 < 16) {
                    iA2 = 16;
                }
                LinkedHashMap linkedHashMap3 = new LinkedHashMap(iA2);
                for (Object obj4 : list2) {
                    linkedHashMap3.put(Long.valueOf(((StudySetWithCreator) obj4).a.a), obj4);
                }
                for (F f2 : remoteData2.a) {
                    StudySetWithCreator studySetWithCreator2 = (StudySetWithCreator) linkedHashMap3.get(Long.valueOf(f2.c));
                    if (studySetWithCreator2 != null) {
                        long j = f2.b;
                        if (linkedHashMap2.get(Long.valueOf(j)) == null) {
                            linkedHashMap2.put(Long.valueOf(j), new ArrayList());
                        }
                        List list3 = (List) linkedHashMap2.get(Long.valueOf(j));
                        if (list3 != null) {
                            list3.add(new C4117c2(studySetWithCreator2.a, studySetWithCreator2.b, f2.g, f2.f, null));
                        }
                    }
                }
                return linkedHashMap2;
        }
    }
}
