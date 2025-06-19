package com.quizlet.quizletandroid.ui.diagramming.data;

import com.quizlet.db.data.models.persisted.DBImageRef;
import com.quizlet.db.data.models.persisted.DBStudySet;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.functions.i;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements i, h {
    public static final a b = new a(0);
    public static final a c = new a(1);
    public static final a d = new a(2);
    public static final a e = new a(3);
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 1:
                List data = (List) obj;
                Intrinsics.checkNotNullParameter(data, "data");
                return (DBImageRef) CollectionsKt.L(data);
            default:
                List data2 = (List) obj;
                Intrinsics.checkNotNullParameter(data2, "data");
                return (DBStudySet) CollectionsKt.L(data2);
        }
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        switch (this.a) {
            case 0:
                List list = (List) obj;
                Intrinsics.checkNotNullParameter(list, "list");
                return !list.isEmpty();
            default:
                List list2 = (List) obj;
                Intrinsics.checkNotNullParameter(list2, "list");
                return !list2.isEmpty();
        }
    }
}
