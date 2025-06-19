package com.quizlet.remote.model.union.folderwithcreator;

import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.bookmark.BookmarkResponse;
import com.quizlet.remote.model.bookmark.RemoteBookmark;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h {
    public static final a a = new a();

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        BookmarkResponse.Models models;
        List list;
        ApiThreeWrapper response = (ApiThreeWrapper) obj;
        Intrinsics.checkNotNullParameter(response, "response");
        BookmarkResponse bookmarkResponse = (BookmarkResponse) response.a();
        if (bookmarkResponse == null || (models = bookmarkResponse.d) == null || (list = models.a) == null) {
            return K.a;
        }
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            arrayList.add(Long.valueOf(((RemoteBookmark) it2.next()).c));
        }
        return arrayList;
    }
}
