package com.quizlet.search.data.blended;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.E0;
import com.quizlet.data.model.C4113b2;
import com.quizlet.data.model.C4136i1;
import com.quizlet.data.model.C4154o1;
import com.quizlet.data.model.C4172v;
import com.quizlet.data.model.C4183y1;
import com.quizlet.data.model.StudySet;
import com.quizlet.data.model.Textbook;
import com.quizlet.data.model.User;
import com.quizlet.data.model.i2;
import com.quizlet.data.model.j2;
import com.quizlet.generated.enums.EnumC4478e1;
import com.quizlet.search.data.term.TermSearchUiModel;
import com.quizlet.search.data.term.TermUiModel;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.CollectionsKt;
import kotlin.collections.G;
import kotlin.collections.K;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.C;
import kotlinx.coroutines.C4980e;
import kotlinx.coroutines.E;
import kotlinx.coroutines.H;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ String l;
    public final /* synthetic */ com.quizlet.data.repository.folderwithcreatorinclass.e m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(com.quizlet.data.repository.folderwithcreatorinclass.e eVar, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = str;
        this.m = eVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        f fVar = new f(this.m, this.l, hVar);
        fVar.k = obj;
        return fVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r4v4, types: [java.lang.Iterable, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r4v6, types: [java.lang.Iterable, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r6v2, types: [java.lang.Iterable, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r6v4, types: [java.lang.Iterable, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r6v6, types: [java.lang.Iterable, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r6v8, types: [java.lang.Iterable, java.lang.Object] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objA;
        Iterable iterableH;
        String str;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar = this.m;
        if (i == 0) {
            Z.e(obj);
            C c = (C) this.k;
            String str2 = this.l;
            if (StringsKt.O(str2)) {
                com.quizlet.ui.models.search.b bVar = com.quizlet.ui.models.search.b.a;
                eVar.getClass();
                return new a("", A.b(bVar), K.a);
            }
            H[] hArr = {E.f(c, null, new c(eVar, null), 3), E.f(c, null, new e(eVar, str2, null), 3), E.f(c, null, new d(eVar, str2, null), 3)};
            this.j = 1;
            objA = new C4980e(hArr).a(this);
            if (objA == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            objA = obj;
        }
        List list = (List) objA;
        Object objL = CollectionsKt.L(list);
        Intrinsics.e(objL, "null cannot be cast to non-null type kotlin.Boolean");
        boolean zBooleanValue = ((Boolean) objL).booleanValue();
        Object obj2 = list.get(1);
        com.quizlet.ui.models.search.c cVar = obj2 instanceof com.quizlet.ui.models.search.c ? (com.quizlet.ui.models.search.c) obj2 : null;
        Object objU = CollectionsKt.U(list);
        Intrinsics.e(objU, "null cannot be cast to non-null type com.quizlet.data.model.SearchAllResultsWrapper");
        C4183y1 c4183y1 = (C4183y1) objU;
        C4172v c4172v = c4183y1.a;
        Collection collectionB = cVar != null ? A.b(cVar) : K.a;
        eVar.getClass();
        ?? r6 = c4172v.a;
        Intrinsics.checkNotNullParameter(r6, "<this>");
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(r6, 10));
        Iterator it2 = r6.iterator();
        while (it2.hasNext()) {
            arrayList.add(E0.d((C4113b2) it2.next()));
        }
        ?? r62 = c4172v.d;
        Intrinsics.checkNotNullParameter(r62, "<this>");
        ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(r62, 10));
        Iterator it3 = r62.iterator();
        while (it3.hasNext()) {
            arrayList2.add(E0.f((User) it3.next()));
        }
        ?? r63 = c4172v.c;
        Intrinsics.checkNotNullParameter(r63, "<this>");
        ArrayList arrayList3 = new ArrayList(kotlin.collections.C.q(r63, 10));
        Iterator it4 = r63.iterator();
        while (it4.hasNext()) {
            arrayList3.add(E0.c((C4154o1) it4.next(), zBooleanValue));
        }
        ?? r64 = c4172v.b;
        Intrinsics.checkNotNullParameter(r64, "<this>");
        ArrayList arrayList4 = new ArrayList(kotlin.collections.C.q(r64, 10));
        Iterator it5 = r64.iterator();
        while (it5.hasNext()) {
            arrayList4.add(E0.e((Textbook) it5.next(), zBooleanValue));
        }
        ?? r4 = c4172v.e;
        Intrinsics.checkNotNullParameter(r4, "<this>");
        ArrayList arrayList5 = new ArrayList(kotlin.collections.C.q(r4, 10));
        Iterator it6 = r4.iterator();
        while (it6.hasNext()) {
            arrayList5.add(E0.b((C4136i1) it6.next()));
        }
        ?? r42 = c4172v.f;
        Intrinsics.checkNotNullParameter(r42, "<this>");
        ArrayList arrayList6 = new ArrayList(kotlin.collections.C.q(r42, 10));
        Iterator it7 = r42.iterator();
        while (it7.hasNext()) {
            j2 j2Var = (j2) it7.next();
            Intrinsics.checkNotNullParameter(j2Var, "<this>");
            i2 i2Var = j2Var.a;
            StudySet studySet = j2Var.b;
            Iterator it8 = it7;
            Collection collection = collectionB;
            long j = studySet != null ? studySet.a : 0L;
            long j2 = studySet != null ? studySet.e : 0L;
            String str3 = (studySet == null || (str = studySet.h) == null) ? "" : str;
            int i2 = studySet != null ? studySet.n : 0;
            String str4 = i2Var.f;
            if (str4 == null) {
                str4 = "";
            }
            arrayList6.add(new TermSearchUiModel(i2Var.a, j, j2, str3, i2, new TermUiModel(i2Var.e, str4, i2Var.g)));
            collectionB = collection;
            it7 = it8;
        }
        Collection collection2 = collectionB;
        List list2 = c4172v.g;
        List list3 = list2.isEmpty() ? (List) eVar.e : list2;
        ArrayList arrayList7 = new ArrayList();
        Iterator it9 = list3.iterator();
        while (it9.hasNext()) {
            switch (b.a[((EnumC4478e1) it9.next()).ordinal()]) {
                case 1:
                    iterableH = com.quizlet.data.repository.folderwithcreatorinclass.e.h(arrayList5, com.quizlet.search.data.a.e);
                    break;
                case 2:
                    iterableH = com.quizlet.data.repository.folderwithcreatorinclass.e.h(arrayList3, com.quizlet.search.data.a.c);
                    break;
                case 3:
                    iterableH = com.quizlet.data.repository.folderwithcreatorinclass.e.h(arrayList, com.quizlet.search.data.a.a);
                    break;
                case 4:
                    iterableH = com.quizlet.data.repository.folderwithcreatorinclass.e.h(arrayList6, com.quizlet.search.data.a.f);
                    break;
                case 5:
                    iterableH = com.quizlet.data.repository.folderwithcreatorinclass.e.h(arrayList4, com.quizlet.search.data.a.b);
                    break;
                case 6:
                    iterableH = com.quizlet.data.repository.folderwithcreatorinclass.e.h(arrayList2, com.quizlet.search.data.a.d);
                    break;
                default:
                    iterableH = K.a;
                    break;
            }
            G.u(arrayList7, iterableH);
        }
        boolean zIsEmpty = arrayList7.isEmpty();
        Collection collectionB2 = arrayList7;
        if (zIsEmpty) {
            collectionB2 = A.b(com.quizlet.ui.models.search.b.a);
        }
        return new a(c4183y1.b, CollectionsKt.c0(collection2, collectionB2), list2);
    }
}
