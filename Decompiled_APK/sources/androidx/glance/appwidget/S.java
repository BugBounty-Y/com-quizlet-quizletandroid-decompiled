package androidx.glance.appwidget;

import com.quizlet.quizletandroid.ui.widgets.QuizletWidgetReceiver;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class S extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ ArrayList k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public S(ArrayList arrayList, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = arrayList;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        S s = new S(this.k, hVar);
        s.j = obj;
        return s;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((S) create((androidx.datastore.preferences.core.b) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        androidx.datastore.preferences.core.b bVarG = ((androidx.datastore.preferences.core.b) this.j).g();
        androidx.datastore.preferences.core.f fVar = X.g;
        ArrayList arrayList = this.k;
        ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            arrayList2.add(((QuizletWidgetReceiver) it2.next()).getClass().getName());
        }
        bVarG.e(fVar, CollectionsKt.A0(arrayList2));
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            QuizletWidgetReceiver quizletWidgetReceiver = (QuizletWidgetReceiver) it3.next();
            P p = X.d;
            p.getClass();
            String canonicalName = quizletWidgetReceiver.getClass().getCanonicalName();
            if (canonicalName == null) {
                throw new IllegalArgumentException("no receiver name");
            }
            androidx.datastore.preferences.core.f key = P.a(p, canonicalName);
            String canonicalName2 = com.quizlet.quizletandroid.ui.widgets.y.c.getClass().getCanonicalName();
            if (canonicalName2 == null) {
                throw new IllegalArgumentException("no provider name");
            }
            Intrinsics.checkNotNullParameter(key, "key");
            bVarG.f(key, canonicalName2);
        }
        return bVarG.h();
    }
}
