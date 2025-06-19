package com.google.android.gms.tasks;

import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.quizlet.data.model.C4117c2;
import com.quizlet.data.model.D;
import com.quizlet.data.model.F;
import com.quizlet.data.model.G;
import com.quizlet.data.model.H;
import com.quizlet.data.model.StudySetWithCreator;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.collections.C;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class n implements a, io.reactivex.rxjava3.functions.h {
    public final /* synthetic */ int a;
    public final /* synthetic */ List b;

    public /* synthetic */ n(List list, int i) {
        this.a = i;
        this.b = list;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 1:
                List<H> folderWithCreators = (List) obj;
                Intrinsics.checkNotNullParameter(folderWithCreators, "folderWithCreators");
                List list = this.b;
                int iA = U.a(C.q(list, 10));
                if (iA < 16) {
                    iA = 16;
                }
                LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
                for (Object obj2 : list) {
                    linkedHashMap.put(Long.valueOf(((D) obj2).c), obj2);
                }
                ArrayList arrayList = new ArrayList();
                for (H h : folderWithCreators) {
                    D d = (D) linkedHashMap.get(Long.valueOf(h.a.l));
                    G g = d != null ? new G(h.a, h.b, d.e, d.d) : null;
                    if (g != null) {
                        arrayList.add(g);
                    }
                }
                break;
            case 2:
                List<StudySetWithCreator> studySetWithCreators = (List) obj;
                Intrinsics.checkNotNullParameter(studySetWithCreators, "studySetWithCreators");
                List list2 = this.b;
                int iA2 = U.a(C.q(list2, 10));
                if (iA2 < 16) {
                    iA2 = 16;
                }
                LinkedHashMap linkedHashMap2 = new LinkedHashMap(iA2);
                for (Object obj3 : list2) {
                    linkedHashMap2.put(Long.valueOf(((F) obj3).c), obj3);
                }
                ArrayList arrayList2 = new ArrayList();
                for (StudySetWithCreator studySetWithCreator : studySetWithCreators) {
                    F f = (F) linkedHashMap2.get(Long.valueOf(studySetWithCreator.a.a));
                    C4117c2 c4117c2 = f != null ? new C4117c2(studySetWithCreator.a, studySetWithCreator.b, f.g, f.f, null) : null;
                    if (c4117c2 != null) {
                        arrayList2.add(c4117c2);
                    }
                }
                break;
            case 3:
                Boolean it2 = (Boolean) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                break;
            default:
                Intrinsics.checkNotNullParameter((List) obj, "<unused var>");
                break;
        }
        return this.b;
    }

    @Override // com.google.android.gms.tasks.a
    public /* bridge */ /* synthetic */ Object h(Task task) {
        ArrayList arrayList = new ArrayList();
        arrayList.addAll(this.b);
        return S3.i(arrayList);
    }
}
