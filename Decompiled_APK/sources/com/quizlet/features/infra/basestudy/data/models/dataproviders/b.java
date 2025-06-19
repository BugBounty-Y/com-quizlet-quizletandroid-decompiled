package com.quizlet.features.infra.basestudy.data.models.dataproviders;

import androidx.collection.C0219q;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.db.data.models.interfaces.StudyableModel;
import com.quizlet.db.data.models.persisted.DBDiagramShape;
import com.quizlet.db.data.models.persisted.DBSelectedTerm;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.features.flashcards.C4237k;
import com.quizlet.generated.enums.O1;
import io.reactivex.rxjava3.functions.e;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.functions.i;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements h, i, io.reactivex.rxjava3.functions.b, e {
    public final /* synthetic */ int a;
    public final /* synthetic */ a b;

    public /* synthetic */ b(a aVar, int i) {
        this.a = i;
        this.b = aVar;
    }

    /* JADX WARN: Type inference failed for: r5v1, types: [io.reactivex.rxjava3.subjects.l, java.util.concurrent.atomic.AtomicReference] */
    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        List<DBSession> list = (List) obj;
        switch (this.a) {
            case 0:
                a aVar = this.b;
                aVar.u = list;
                C0219q c0219q = aVar.B;
                c0219q.b();
                List<DBSelectedTerm> list2 = aVar.u;
                if (list2 != null) {
                    for (DBSelectedTerm dBSelectedTerm : list2) {
                        c0219q.g(dBSelectedTerm.getTermId(), dBSelectedTerm);
                    }
                }
                return aVar.u;
            case 1:
                a aVar2 = this.b;
                aVar2.getClass();
                DBSession dBSession = null;
                for (DBSession dBSession2 : list) {
                    if (dBSession2 != null && dBSession2.getSelectedTermsOnly() == ((Boolean) aVar2.h.a.getValue()).booleanValue() && (dBSession == null || dBSession2.getTimestampMs() > dBSession.getTimestampMs())) {
                        dBSession = dBSession2;
                    }
                }
                aVar2.C = dBSession;
                return list;
            case 2:
            default:
                a aVar3 = this.b;
                aVar3.getClass();
                if (list.size() > 1) {
                    timber.log.c.a.d("Somehow we see more than one Studyale model (%d). Opting to go with the first, ignoring the rest. ", Integer.valueOf(list.size()));
                }
                StudyableModel studyableModel = (StudyableModel) list.get(0);
                aVar3.f = studyableModel;
                return studyableModel;
            case 3:
                return this.b.C;
            case 4:
                this.b.D = list;
                return list;
        }
    }

    @Override // io.reactivex.rxjava3.functions.e
    public Object k(Object obj, Object obj2, Object obj3) {
        DBSelectedTerm dBSelectedTerm;
        List list = (List) obj;
        List list2 = (List) obj2;
        boolean zBooleanValue = ((Boolean) obj3).booleanValue();
        a aVar = this.b;
        ArrayList arrayList = aVar.d;
        if (arrayList != null && !arrayList.isEmpty()) {
            aVar.s = new ArrayList();
            for (DBTerm dBTerm : aVar.t) {
                if (arrayList.contains(Long.valueOf(dBTerm.getId()))) {
                    aVar.s.add(dBTerm);
                }
            }
        } else if (zBooleanValue && list != null && list2 != null) {
            aVar.s = new ArrayList();
            for (DBTerm dBTerm2 : aVar.t) {
                if (dBTerm2 == null) {
                    dBSelectedTerm = null;
                } else {
                    long id = dBTerm2.getId();
                    long localId = dBTerm2.getLocalId();
                    C0219q c0219q = aVar.B;
                    dBSelectedTerm = (DBSelectedTerm) c0219q.d(id, (DBSelectedTerm) c0219q.d(localId, null));
                }
                if (dBSelectedTerm != null) {
                    aVar.s.add(dBTerm2);
                }
            }
        } else if (aVar.t != null) {
            aVar.s = new ArrayList(aVar.t);
        } else {
            aVar.s = null;
        }
        return aVar.s;
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        List list = (List) obj;
        switch (this.a) {
            case 2:
                return this.b.C != null;
            case 5:
                return this.b.f != null;
            default:
                a aVar = this.b;
                if (list == null) {
                    aVar.getClass();
                    return false;
                }
                aVar.t = list;
                return true;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r10v5, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r10v6, types: [java.lang.Iterable, java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r10v9, types: [java.util.List] */
    @Override // io.reactivex.rxjava3.functions.b
    public Object apply(Object obj, Object obj2) {
        Object next;
        ?? K;
        List<DBTerm> terms = (List) obj;
        List<DBDiagramShape> diagramShapes = (List) obj2;
        a aVar = this.b;
        aVar.A.getClass();
        Intrinsics.checkNotNullParameter(terms, "terms");
        Intrinsics.checkNotNullParameter(diagramShapes, "diagramShapes");
        if (diagramShapes == null || !diagramShapes.isEmpty()) {
            for (DBDiagramShape dBDiagramShape : diagramShapes) {
                Iterator it2 = terms.iterator();
                while (true) {
                    if (!it2.hasNext()) {
                        next = null;
                        break;
                    }
                    next = it2.next();
                    if (((DBTerm) next).getId() == dBDiagramShape.getTermId()) {
                        break;
                    }
                }
                if (next != null) {
                    K = B.k(O1.LOCATION);
                    if (!terms.isEmpty()) {
                        Iterator it3 = terms.iterator();
                        while (true) {
                            if (!it3.hasNext()) {
                                break;
                            }
                            String word = ((DBTerm) it3.next()).getWord();
                            if (word != null && word.length() > 0) {
                                K.add(O1.WORD);
                                break;
                            }
                        }
                    }
                    if (!terms.isEmpty()) {
                        for (DBTerm dBTerm : terms) {
                            String definition = dBTerm.getDefinition();
                            if ((definition != null && definition.length() > 0) || dBTerm.hasDefinitionImage()) {
                                K.add(O1.DEFINITION);
                                break;
                            }
                        }
                    }
                }
            }
            K = B.j(O1.WORD, O1.DEFINITION);
        } else {
            K = B.j(O1.WORD, O1.DEFINITION);
        }
        aVar.y = K;
        C4237k transform = new C4237k(12);
        Intrinsics.checkNotNullParameter(K, "<this>");
        Intrinsics.checkNotNullParameter(transform, "transform");
        ArrayList arrayList = new ArrayList(C.q(K, 10));
        Iterator it4 = K.iterator();
        while (it4.hasNext()) {
            arrayList.add(AbstractC3106b5.f((O1) it4.next()));
        }
        aVar.z = arrayList;
        return aVar.y;
    }
}
