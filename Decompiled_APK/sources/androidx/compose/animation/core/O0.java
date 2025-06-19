package androidx.compose.animation.core;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;

/* loaded from: classes.dex */
public final class O0 implements InterfaceC0269u, io.reactivex.rxjava3.functions.b {
    public final ArrayList a;

    public O0(ArrayList arrayList) {
        this.a = arrayList;
    }

    public void a(Object obj) {
        if (obj == null) {
            return;
        }
        boolean z = obj instanceof Object[];
        ArrayList arrayList = this.a;
        if (z) {
            Object[] objArr = (Object[]) obj;
            if (objArr.length > 0) {
                arrayList.ensureCapacity(arrayList.size() + objArr.length);
                Collections.addAll(arrayList, objArr);
                return;
            }
            return;
        }
        if (obj instanceof Collection) {
            arrayList.addAll((Collection) obj);
            return;
        }
        if (obj instanceof Iterable) {
            Iterator it2 = ((Iterable) obj).iterator();
            while (it2.hasNext()) {
                arrayList.add(it2.next());
            }
        } else {
            if (!(obj instanceof Iterator)) {
                throw new UnsupportedOperationException("Don't know how to spread " + obj.getClass());
            }
            Iterator it3 = (Iterator) obj;
            while (it3.hasNext()) {
                arrayList.add(it3.next());
            }
        }
    }

    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object obj, Object obj2) {
        List answers = (List) obj;
        List questionAttributes = (List) obj2;
        Intrinsics.checkNotNullParameter(answers, "answers");
        Intrinsics.checkNotNullParameter(questionAttributes, "questionAttributes");
        return com.quizlet.features.infra.basestudy.utils.b.f(answers, this.a, questionAttributes);
    }

    @Override // androidx.compose.animation.core.InterfaceC0269u
    public E get(int i) {
        return (G) this.a.get(i);
    }

    public O0(Iterable studiableItemIds, List questionTypes) {
        Intrinsics.checkNotNullParameter(questionTypes, "questionTypes");
        Intrinsics.checkNotNullParameter(studiableItemIds, "studiableItemIds");
        ArrayList arrayListE = CollectionsKt.E(studiableItemIds, 10);
        ArrayList arrayList = new ArrayList();
        Iterator it2 = arrayListE.iterator();
        while (it2.hasNext()) {
            List list = (List) it2.next();
            ArrayList arrayList2 = new ArrayList();
            Iterator it3 = questionTypes.iterator();
            while (it3.hasNext()) {
                assistantMode.enums.k kVar = (assistantMode.enums.k) it3.next();
                ArrayList arrayList3 = new ArrayList(kotlin.collections.C.q(list, 10));
                Iterator it4 = list.iterator();
                while (it4.hasNext()) {
                    arrayList3.add(new assistantMode.types.q(((Number) it4.next()).longValue(), kVar));
                }
                kotlin.collections.G.u(arrayList2, arrayList3);
            }
            kotlin.collections.G.u(arrayList, arrayList2);
        }
        this.a = CollectionsKt.y0(arrayList);
    }

    public O0() {
        this.a = new ArrayList(2);
    }

    public O0(float f, float f2, AbstractC0267t abstractC0267t) {
        IntRange intRangeH = kotlin.ranges.l.h(0, abstractC0267t.b());
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(intRangeH, 10));
        kotlin.ranges.i it2 = intRangeH.iterator();
        while (it2.c) {
            arrayList.add(new G(f, f2, abstractC0267t.a(it2.nextInt())));
        }
        this.a = arrayList;
    }
}
