package com.quizlet.data.repository.folderwithcreatorinclass;

import com.quizlet.data.model.AbstractC4119d0;
import com.quizlet.data.model.C4132h0;
import com.quizlet.data.model.ContentFolder;
import com.quizlet.data.model.D;
import com.quizlet.data.model.G;
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
public final class d implements h, io.reactivex.rxjava3.functions.b {
    public static final d a = new d();

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
        a remoteData = (a) obj;
        Intrinsics.checkNotNullParameter(remoteData, "remoteData");
        List list = remoteData.a;
        ArrayList arrayList = new ArrayList();
        for (Object obj2 : list) {
            if (!Intrinsics.b(((D) obj2).f, Boolean.TRUE)) {
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
            linkedHashMap.put(Long.valueOf(((D) next).c), next);
        }
        ArrayList arrayList2 = new ArrayList();
        for (Object obj3 : remoteData.b) {
            AbstractC4119d0 abstractC4119d0 = ((C4132h0) obj3).a;
            if (!abstractC4119d0.d() && (abstractC4119d0 instanceof ContentFolder)) {
                arrayList2.add(obj3);
            }
        }
        ArrayList arrayList3 = new ArrayList();
        Iterator it3 = arrayList2.iterator();
        while (it3.hasNext()) {
            C4132h0 c4132h0 = (C4132h0) it3.next();
            D d = (D) linkedHashMap.get(Long.valueOf(c4132h0.a.a()));
            G g = null;
            if (d != null) {
                AbstractC4119d0 abstractC4119d02 = c4132h0.a;
                Intrinsics.e(abstractC4119d02, "null cannot be cast to non-null type com.quizlet.data.model.ContentFolder");
                ContentFolder contentFolder = (ContentFolder) abstractC4119d02;
                User user = c4132h0.b;
                if (user != 0) {
                    Intrinsics.checkNotNullParameter(user, "<this>");
                    if (!user.l) {
                        g = user;
                    }
                }
                g = new G(contentFolder, g, d.e, d.d);
            }
            if (g != null) {
                arrayList3.add(g);
            }
        }
        return arrayList3;
    }
}
