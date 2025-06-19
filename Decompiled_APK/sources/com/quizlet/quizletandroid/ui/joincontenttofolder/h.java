package com.quizlet.quizletandroid.ui.joincontenttofolder;

import com.quizlet.data.model.C4123e0;
import com.quizlet.data.model.D;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Pair;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ k b;

    public /* synthetic */ h(k kVar, int i) {
        this.a = i;
        this.b = kVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                Throwable error = (Throwable) obj;
                Intrinsics.checkNotNullParameter(error, "error");
                timber.log.c.a.q(error, "Encountered error saving ClassFolders", new Object[0]);
                this.b.r.l(new d());
                break;
            case 1:
                Throwable error2 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(error2, "error");
                timber.log.c.a.q(error2, "Encountered error saving FolderSets", new Object[0]);
                this.b.r.l(new d());
                break;
            case 2:
                Pair pair = (Pair) obj;
                Intrinsics.checkNotNullParameter(pair, "<destruct>");
                List list = (List) pair.a;
                List list2 = (List) pair.b;
                ArrayList arrayList = new ArrayList(C.q(list, 10));
                Iterator it2 = list.iterator();
                while (it2.hasNext()) {
                    arrayList.add(Long.valueOf(((D) it2.next()).c));
                }
                k kVar = this.b;
                kVar.o = arrayList;
                k.B(kVar, list2, arrayList);
                break;
            case 3:
                Throwable error3 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(error3, "error");
                timber.log.c.a.q(error3, "Encountered error getting ClassFolders or FoldersWithCreators", new Object[0]);
                this.b.r.l(new d());
                break;
            case 4:
                Pair pair2 = (Pair) obj;
                Intrinsics.checkNotNullParameter(pair2, "<destruct>");
                List list3 = (List) pair2.a;
                List list4 = (List) pair2.b;
                k kVar2 = this.b;
                kVar2.n = list3;
                ArrayList arrayList2 = new ArrayList(C.q(list3, 10));
                Iterator it3 = list3.iterator();
                while (it3.hasNext()) {
                    arrayList2.add(Long.valueOf(((C4123e0) it3.next()).c));
                }
                k.B(kVar2, list4, arrayList2);
                break;
            default:
                Throwable error4 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(error4, "error");
                timber.log.c.a.q(error4, "Encountered error getting FolderSets or FoldersWithCreators", new Object[0]);
                this.b.r.l(new d());
                break;
        }
    }
}
