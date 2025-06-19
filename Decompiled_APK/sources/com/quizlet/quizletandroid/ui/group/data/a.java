package com.quizlet.quizletandroid.ui.group.data;

import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.db.data.models.persisted.DBGroupMembership;
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
                List list = (List) obj;
                Intrinsics.checkNotNullParameter(list, "list");
                return (DBGroupMembership) CollectionsKt.L(list);
            default:
                List list2 = (List) obj;
                Intrinsics.checkNotNullParameter(list2, "list");
                return (DBGroup) CollectionsKt.L(list2);
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
