package com.quizlet.quizletandroid.ui.setcreation.viewmodels;

import androidx.lifecycle.X;
import com.google.android.gms.internal.ads.Zh;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.scandocument.model.A;
import com.quizlet.scandocument.model.i;
import com.quizlet.scandocument.model.k;
import com.quizlet.scandocument.model.l;
import com.quizlet.scandocument.model.r;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class g implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ h b;

    public /* synthetic */ g(h hVar, int i) {
        this.a = i;
        this.b = hVar;
    }

    /* JADX WARN: Type inference failed for: r0v8, types: [java.lang.Object, java.util.Collection] */
    /* JADX WARN: Type inference failed for: r14v14, types: [java.lang.Iterable, java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r6v4, types: [java.lang.Object, java.util.List] */
    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        l lVar;
        int i = 2;
        int i2 = 1;
        h hVar = this.b;
        switch (this.a) {
            case 0:
                DBStudySet studySet = (DBStudySet) obj;
                Intrinsics.checkNotNullParameter(studySet, "studySet");
                Zh zh = hVar.c;
                DBStudySet dBStudySet = (DBStudySet) zh.i;
                if (org.apache.commons.lang3.e.c(dBStudySet != null ? dBStudySet.getWordLang() : null)) {
                    return;
                }
                DBStudySet dBStudySet2 = (DBStudySet) zh.i;
                if (org.apache.commons.lang3.e.c(dBStudySet2 != null ? dBStudySet2.getDefLang() : null)) {
                    return;
                }
                hVar.F(studySet.getTitle());
                return;
            case 1:
                ((Number) obj).intValue();
                StringBuilder sb = new StringBuilder();
                ArrayList arrayList = hVar.o;
                if (!arrayList.isEmpty()) {
                    sb.append(CollectionsKt.S(arrayList, " ", null, null, null, 62));
                    sb.append(" ");
                }
                Iterator it2 = hVar.e.b.iterator();
                List list = com.quizlet.quizletandroid.util.f.d;
                com.quizlet.scandocument.model.h hVar2 = hVar.p;
                if (hVar2 == null) {
                    Intrinsics.m("ocrDocument");
                    throw null;
                }
                String locale = hVar2.b.a;
                Intrinsics.checkNotNullParameter(locale, "locale");
                String str = com.quizlet.quizletandroid.util.f.d.contains(locale) ? "" : " ";
                while (it2.hasNext()) {
                    int iIntValue = ((Number) it2.next()).intValue();
                    com.quizlet.scandocument.model.h hVar3 = hVar.p;
                    if (hVar3 == null) {
                        Intrinsics.m("ocrDocument");
                        throw null;
                    }
                    sb.append(((com.quizlet.scandocument.model.c) hVar3.b.b.get(iIntValue)).a);
                    sb.append(str);
                }
                String string = sb.toString();
                Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                String string2 = StringsKt.g0(string).toString();
                if (StringsKt.O(string2)) {
                    return;
                }
                hVar.m.l(string2);
                return;
            case 2:
                Intrinsics.checkNotNullParameter((Throwable) obj, "p0");
                hVar.getClass();
                return;
            case 3:
                com.quizlet.scandocument.model.h p0 = (com.quizlet.scandocument.model.h) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                hVar.getClass();
                boolean zIsEmpty = p0.b.b.isEmpty();
                com.quizlet.quizletandroid.ui.setcreation.tracking.c cVar = hVar.f;
                if (zIsEmpty) {
                    cVar.a(com.quizlet.quizletandroid.ui.setcreation.tracking.b.d);
                    hVar.q = l.e;
                } else {
                    hVar.q = new k(p0);
                    hVar.p = p0;
                    ?? annotations = p0.b.b;
                    com.quizlet.scandocument.a aVar = hVar.e;
                    aVar.getClass();
                    Intrinsics.checkNotNullParameter(annotations, "annotations");
                    ArrayList arrayList2 = new ArrayList(C.q(annotations, 10));
                    Iterator it3 = annotations.iterator();
                    while (it3.hasNext()) {
                        ArrayList arrayList3 = ((com.quizlet.scandocument.model.c) it3.next()).b.a;
                        ArrayList arrayList4 = new ArrayList(C.q(arrayList3, 10));
                        Iterator it4 = arrayList3.iterator();
                        while (it4.hasNext()) {
                            i iVar = (i) it4.next();
                            arrayList4.add(new com.quizlet.scandocument.graphics.a(iVar.a, iVar.b));
                        }
                        arrayList2.add(new com.quizlet.scandocument.graphics.b((com.quizlet.scandocument.graphics.a) arrayList4.get(0), (com.quizlet.scandocument.graphics.a) arrayList4.get(1), (com.quizlet.scandocument.graphics.a) arrayList4.get(2), (com.quizlet.scandocument.graphics.a) arrayList4.get(3)));
                    }
                    aVar.b.clear();
                    aVar.c.clear();
                    ArrayList arrayList5 = aVar.a;
                    arrayList5.clear();
                    arrayList5.addAll(arrayList2);
                    cVar.a.a(annotations.size());
                    io.reactivex.rxjava3.disposables.b bVarU = aVar.d.u(new g(hVar, i2), new g(hVar, i), io.reactivex.rxjava3.internal.functions.d.c);
                    Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
                    Intrinsics.checkNotNullParameter(bVarU, "<this>");
                    hVar.A(bVarU);
                }
                hVar.g.j(hVar.q);
                return;
            case 4:
                Throwable p02 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(p02, "p0");
                hVar.getClass();
                boolean z = p02 instanceof SocketTimeoutException;
                com.quizlet.quizletandroid.ui.setcreation.tracking.c cVar2 = hVar.f;
                if (z) {
                    cVar2.a(com.quizlet.quizletandroid.ui.setcreation.tracking.b.b);
                    lVar = l.c;
                } else if (p02 instanceof UnknownHostException) {
                    cVar2.a(com.quizlet.quizletandroid.ui.setcreation.tracking.b.e);
                    lVar = l.f;
                } else {
                    cVar2.a(com.quizlet.quizletandroid.ui.setcreation.tracking.b.c);
                    lVar = l.d;
                }
                hVar.q = lVar;
                hVar.g.j(lVar);
                return;
            case 5:
                A a = (A) obj;
                X x = hVar.i;
                Intrinsics.d(a);
                x.j(a);
                return;
            case 6:
                Throwable error = (Throwable) obj;
                Intrinsics.checkNotNullParameter(error, "error");
                hVar.i.j(new r(error));
                return;
            default:
                hVar.l.j(Integer.valueOf(((Number) obj).intValue()));
                return;
        }
    }
}
