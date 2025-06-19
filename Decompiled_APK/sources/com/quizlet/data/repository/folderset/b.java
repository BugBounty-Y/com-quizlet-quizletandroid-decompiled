package com.quizlet.data.repository.folderset;

import com.quizlet.data.model.C4123e0;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.collections.CollectionsKt;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b implements h, io.reactivex.rxjava3.functions.b {
    public static final b b = new b(0);
    public static final b c = new b(1);
    public static final b d = new b(2);
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object obj, Object obj2) {
        List created = (List) obj;
        List deleted = (List) obj2;
        Intrinsics.checkNotNullParameter(created, "created");
        Intrinsics.checkNotNullParameter(deleted, "deleted");
        return CollectionsKt.c0(created, deleted);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 0:
                List list = (List) obj;
                ArrayList arrayListM = assistantMode.refactored.a.m("folderSets", list);
                for (Object obj2 : list) {
                    if (!Intrinsics.b(((C4123e0) obj2).e, Boolean.TRUE)) {
                        arrayListM.add(obj2);
                    }
                }
                return arrayListM;
            default:
                List folderSets = (List) obj;
                Intrinsics.checkNotNullParameter(folderSets, "folderSets");
                LinkedHashMap linkedHashMap = new LinkedHashMap();
                for (Object obj3 : folderSets) {
                    Long lValueOf = Long.valueOf(((C4123e0) obj3).c);
                    Object arrayList = linkedHashMap.get(lValueOf);
                    if (arrayList == null) {
                        arrayList = new ArrayList();
                        linkedHashMap.put(lValueOf, arrayList);
                    }
                    ((List) arrayList).add(obj3);
                }
                LinkedHashMap linkedHashMap2 = new LinkedHashMap(U.a(linkedHashMap.size()));
                for (Map.Entry entry : linkedHashMap.entrySet()) {
                    linkedHashMap2.put(entry.getKey(), Integer.valueOf(((List) entry.getValue()).size()));
                }
                return linkedHashMap2;
        }
    }
}
