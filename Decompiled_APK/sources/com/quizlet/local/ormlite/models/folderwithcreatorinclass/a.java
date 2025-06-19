package com.quizlet.local.ormlite.models.folderwithcreatorinclass;

import com.quizlet.data.model.AbstractC4119d0;
import com.quizlet.data.model.C4132h0;
import com.quizlet.data.model.ContentFolder;
import com.quizlet.data.model.H;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h {
    public static final a a = new a();

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        List list = (List) obj;
        ArrayList arrayListM = assistantMode.refactored.a.m("data", list);
        for (Object obj2 : list) {
            if (((C4132h0) obj2).a instanceof ContentFolder) {
                arrayListM.add(obj2);
            }
        }
        ArrayList arrayList = new ArrayList(C.q(arrayListM, 10));
        Iterator it2 = arrayListM.iterator();
        while (it2.hasNext()) {
            C4132h0 c4132h0 = (C4132h0) it2.next();
            AbstractC4119d0 abstractC4119d0 = c4132h0.a;
            Intrinsics.e(abstractC4119d0, "null cannot be cast to non-null type com.quizlet.data.model.ContentFolder");
            arrayList.add(new H((ContentFolder) abstractC4119d0, c4132h0.b));
        }
        return arrayList;
    }
}
