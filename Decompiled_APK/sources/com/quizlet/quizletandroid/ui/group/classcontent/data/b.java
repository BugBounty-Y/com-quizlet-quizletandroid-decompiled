package com.quizlet.quizletandroid.ui.group.classcontent.data;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3179j6;
import com.quizlet.data.model.C4117c2;
import com.quizlet.data.model.ContentFolder;
import com.quizlet.data.model.G;
import com.quizlet.data.model.StudySet;
import com.quizlet.data.model.User;
import com.quizlet.quizletandroid.ui.group.classcontent.models.c;
import com.quizlet.quizletandroid.ui.group.classcontent.models.d;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements h, io.reactivex.rxjava3.functions.b {
    public static final b b = new b(0);
    public static final b c = new b(1);
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object t1, Object t2) {
        Intrinsics.checkNotNullExpressionValue(t1, "t1");
        Intrinsics.checkNotNullExpressionValue(t2, "t2");
        List list = (List) t2;
        List list2 = (List) t1;
        Intrinsics.d(list2);
        Intrinsics.d(list);
        return CollectionsKt.n0(CollectionsKt.c0(list2, list), new a());
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        com.quizlet.quizletandroid.ui.group.classcontent.models.b bVar;
        com.quizlet.quizletandroid.ui.group.classcontent.models.b bVar2;
        switch (this.a) {
            case 0:
                List<G> dataList = (List) obj;
                Intrinsics.checkNotNullParameter(dataList, "dataList");
                ArrayList arrayList = new ArrayList(C.q(dataList, 10));
                for (G g : dataList) {
                    Intrinsics.checkNotNullParameter(g, "<this>");
                    long j = g.a.l;
                    User user = g.b;
                    if (user != null) {
                        Intrinsics.checkNotNullParameter(user, "<this>");
                        bVar = new com.quizlet.quizletandroid.ui.group.classcontent.models.b(user.a, user.b, user.i, user.e, AbstractC3179j6.b(user), user.f, user.g);
                    } else {
                        bVar = null;
                    }
                    com.quizlet.quizletandroid.ui.group.classcontent.models.b bVar3 = bVar;
                    ContentFolder contentFolder = g.a;
                    String str = contentFolder.r;
                    Integer num = contentFolder.x;
                    arrayList.add(new c(j, bVar3, g.d, g.c, str, num != null ? num.intValue() : -1));
                }
                return arrayList;
            default:
                List<C4117c2> dataList2 = (List) obj;
                Intrinsics.checkNotNullParameter(dataList2, "dataList");
                ArrayList arrayList2 = new ArrayList(C.q(dataList2, 10));
                for (C4117c2 c4117c2 : dataList2) {
                    Intrinsics.checkNotNullParameter(c4117c2, "<this>");
                    long j2 = c4117c2.a.a;
                    User user2 = c4117c2.b;
                    if (user2 != null) {
                        Intrinsics.checkNotNullParameter(user2, "<this>");
                        bVar2 = new com.quizlet.quizletandroid.ui.group.classcontent.models.b(user2.a, user2.b, user2.i, user2.e, AbstractC3179j6.b(user2), user2.f, user2.g);
                    } else {
                        bVar2 = null;
                    }
                    StudySet studySet = c4117c2.a;
                    arrayList2.add(new d(j2, bVar2, c4117c2.d, c4117c2.c, studySet.h, studySet.n, studySet.o, studySet.s, studySet.i, studySet.u));
                }
                return arrayList2;
        }
    }
}
