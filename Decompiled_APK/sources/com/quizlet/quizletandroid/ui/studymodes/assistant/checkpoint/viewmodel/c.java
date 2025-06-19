package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel;

import com.quizlet.studiablemodels.StudiableWriteMasteryBuckets;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ d b;

    public /* synthetic */ c(d dVar, int i) {
        this.a = i;
        this.b = dVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter((io.reactivex.rxjava3.disposables.b) obj, "it");
                this.b.e.j(k.a);
                break;
            default:
                List it2 = (List) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                d dVar = this.b;
                StudiableWriteMasteryBuckets studiableWriteMasteryBuckets = dVar.j;
                List list = studiableWriteMasteryBuckets.a;
                ArrayList arrayList = new ArrayList();
                for (Object obj2 : it2) {
                    if (list.contains(Long.valueOf(((com.quizlet.learn.checkpoint.data.d) obj2).a.a))) {
                        arrayList.add(obj2);
                    }
                }
                ArrayList arrayList2 = new ArrayList();
                for (Object obj3 : it2) {
                    if (studiableWriteMasteryBuckets.b.contains(Long.valueOf(((com.quizlet.learn.checkpoint.data.d) obj3).a.a))) {
                        arrayList2.add(obj3);
                    }
                }
                p pVar = new p(arrayList, arrayList2);
                dVar.i = pVar;
                dVar.e.j(new j(pVar.a(dVar.h)));
                break;
        }
    }
}
