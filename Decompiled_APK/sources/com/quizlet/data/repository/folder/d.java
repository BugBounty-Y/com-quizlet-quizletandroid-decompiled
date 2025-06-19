package com.quizlet.data.repository.folder;

import com.quizlet.data.model.CreatedFolder;
import com.quizlet.data.model.P;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C;

/* loaded from: classes2.dex */
public final class d implements io.reactivex.rxjava3.functions.h {
    public static final d a = new d();

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        List list = (List) obj;
        ArrayList arrayListM = assistantMode.refactored.a.m("folders", list);
        for (Object obj2 : list) {
            if (obj2 instanceof CreatedFolder) {
                arrayListM.add(obj2);
            }
        }
        ArrayList arrayList = new ArrayList(C.q(arrayListM, 10));
        Iterator it2 = arrayListM.iterator();
        while (it2.hasNext()) {
            CreatedFolder createdFolder = (CreatedFolder) it2.next();
            arrayList.add(new P(true, createdFolder.a(), createdFolder.b(), true, createdFolder.c()));
        }
        return arrayList;
    }
}
