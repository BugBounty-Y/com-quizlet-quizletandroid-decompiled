package com.quizlet.viewmodel.livedata;

import androidx.lifecycle.X;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final class a implements Function1 {
    public final /* synthetic */ X a;
    public final /* synthetic */ ArrayList b;
    public final /* synthetic */ int c;
    public final /* synthetic */ Function1 d;

    public a(X x, ArrayList arrayList, int i, Function1 function1) {
        this.a = x;
        this.b = arrayList;
        this.c = i;
        this.d = function1;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        X x = this.a;
        if (obj == null && x.d() != null) {
            x.j(null);
        }
        ArrayList arrayList = this.b;
        arrayList.set(this.c, obj);
        Iterator it2 = arrayList.iterator();
        while (true) {
            if (!it2.hasNext()) {
                x.j(this.d.invoke(CollectionsKt.J(arrayList)));
                break;
            }
            if (it2.next() == null) {
                break;
            }
        }
        return Unit.a;
    }
}
