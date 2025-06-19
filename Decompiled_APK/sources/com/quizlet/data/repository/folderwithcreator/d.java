package com.quizlet.data.repository.folderwithcreator;

import com.quizlet.data.model.AbstractC4119d0;
import com.quizlet.data.model.C4132h0;
import com.quizlet.data.model.CreatedFolder;
import com.quizlet.data.model.CreatedFolderWithCreator;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d implements h {
    public static final d a = new d();

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        List list = (List) obj;
        ArrayList arrayListM = assistantMode.refactored.a.m("data", list);
        for (Object obj2 : list) {
            if (((C4132h0) obj2).a instanceof CreatedFolder) {
                arrayListM.add(obj2);
            }
        }
        ArrayList arrayList = new ArrayList(C.q(arrayListM, 10));
        Iterator it2 = arrayListM.iterator();
        while (it2.hasNext()) {
            C4132h0 c4132h0 = (C4132h0) it2.next();
            AbstractC4119d0 abstractC4119d0 = c4132h0.a;
            Intrinsics.e(abstractC4119d0, "null cannot be cast to non-null type com.quizlet.data.model.CreatedFolder");
            arrayList.add(new CreatedFolderWithCreator((CreatedFolder) abstractC4119d0, c4132h0.b));
        }
        return arrayList;
    }
}
