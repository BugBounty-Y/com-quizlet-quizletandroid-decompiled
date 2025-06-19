package com.google.android.gms.internal.mlkit_vision_camera;

import android.os.Bundle;
import android.text.SpannableStringBuilder;
import assistantMode.enums.EnumC1452f;
import assistantMode.refactored.types.StudiableData;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import kotlin.Pair;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class U2 {
    public static final void a(Bundle bundle, long j, long j2, QuestionSettings settings, com.quizlet.generated.enums.A1 studyModeType, boolean z) {
        Intrinsics.checkNotNullParameter(bundle, "<this>");
        Intrinsics.checkNotNullParameter(settings, "settings");
        Intrinsics.checkNotNullParameter(studyModeType, "studyModeType");
        bundle.putLong("ARG_SESSION_ID", j);
        bundle.putLong("ARG_SET_ID", j2);
        bundle.putParcelable("ARG_SETTINGS", settings);
        bundle.putInt("ARG_STUDY_MODE_TYPE", studyModeType.a());
        bundle.putBoolean("ARG_SHOW_FEEDBACK", z);
    }

    public static void b(org.wordpress.aztec.spans.D d, SpannableStringBuilder output, int i, int i2) {
        Intrinsics.checkNotNullParameter(output, "output");
        Intrinsics.checkNotNullParameter(output, "output");
        Intrinsics.checkNotNullParameter(output, "output");
        T2.c(d, output, i, i2);
    }

    public static final assistantMode.refactored.types.flashcards.h c(StudiableData studiableData, List list) {
        List list2 = studiableData.a;
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list2, 10));
        Iterator it2 = list2.iterator();
        while (it2.hasNext()) {
            arrayList.add(Long.valueOf(((assistantMode.refactored.modelTypes.d) it2.next()).getId()));
        }
        HashSet hashSetU0 = CollectionsKt.u0(arrayList);
        ArrayList arrayListD = d(list, hashSetU0);
        ArrayList arrayList2 = new ArrayList();
        Iterator it3 = arrayListD.iterator();
        while (it3.hasNext()) {
            Object next = it3.next();
            int iOrdinal = ((assistantMode.refactored.interfaces.c) next).c().ordinal();
            if (iOrdinal == 1 || iOrdinal == 2) {
                arrayList2.add(next);
            }
        }
        ArrayList elements = new ArrayList(kotlin.collections.C.q(arrayList2, 10));
        Iterator it4 = arrayList2.iterator();
        while (it4.hasNext()) {
            elements.add(Long.valueOf(((assistantMode.refactored.interfaces.c) it4.next()).b()));
        }
        Intrinsics.checkNotNullParameter(hashSetU0, "<this>");
        Intrinsics.checkNotNullParameter(elements, "other");
        LinkedHashSet linkedHashSetZ0 = CollectionsKt.z0(hashSetU0);
        Intrinsics.checkNotNullParameter(linkedHashSetZ0, "<this>");
        Intrinsics.checkNotNullParameter(elements, "elements");
        linkedHashSetZ0.removeAll(kotlin.collections.G.w(elements));
        kotlin.v vVar = null;
        for (assistantMode.refactored.interfaces.c cVar : CollectionsKt.n0(arrayListD, new androidx.constraintlayout.core.e(9))) {
            if (vVar != null) {
                Object obj = vVar.a;
                List list3 = (List) obj;
                if (!list3.contains(Long.valueOf(cVar.b()))) {
                    list3.add(Long.valueOf(cVar.b()));
                    vVar = new kotlin.v(obj, vVar.b, Integer.valueOf((int) cVar.d()));
                }
            }
            vVar = new kotlin.v(kotlin.collections.B.k(Long.valueOf(cVar.b())), Integer.valueOf((int) cVar.d()), Integer.valueOf((int) cVar.d()));
        }
        if (vVar == null) {
            kotlin.collections.M m = kotlin.collections.M.a;
            return new assistantMode.refactored.types.flashcards.h(m, hashSetU0, m, m, m, 1);
        }
        int iIntValue = ((Number) vVar.b).intValue();
        int iIntValue2 = ((Number) vVar.c).intValue();
        ArrayList arrayList3 = new ArrayList();
        Iterator it5 = arrayListD.iterator();
        while (it5.hasNext()) {
            Object next2 = it5.next();
            if (((assistantMode.refactored.interfaces.c) next2).d() >= iIntValue) {
                arrayList3.add(next2);
            }
        }
        ArrayList arrayList4 = new ArrayList();
        Iterator it6 = arrayListD.iterator();
        while (it6.hasNext()) {
            Object next3 = it6.next();
            if (((assistantMode.refactored.interfaces.c) next3).d() == iIntValue2) {
                arrayList4.add(next3);
            }
        }
        ArrayList arrayList5 = new ArrayList(kotlin.collections.C.q(arrayList3, 10));
        Iterator it7 = arrayList3.iterator();
        while (it7.hasNext()) {
            arrayList5.add(Long.valueOf(((assistantMode.refactored.interfaces.c) it7.next()).b()));
        }
        HashSet hashSetU02 = CollectionsKt.u0(arrayList5);
        ArrayList arrayList6 = new ArrayList();
        Iterator it8 = arrayList3.iterator();
        while (it8.hasNext()) {
            Object next4 = it8.next();
            assistantMode.refactored.interfaces.c cVar2 = (assistantMode.refactored.interfaces.c) next4;
            if (cVar2.c() == EnumC1452f.c || cVar2.c() == EnumC1452f.d) {
                arrayList6.add(next4);
            }
        }
        ArrayList arrayList7 = new ArrayList(kotlin.collections.C.q(arrayList6, 10));
        Iterator it9 = arrayList6.iterator();
        while (it9.hasNext()) {
            arrayList7.add(Long.valueOf(((assistantMode.refactored.interfaces.c) it9.next()).b()));
        }
        HashSet hashSetU03 = CollectionsKt.u0(arrayList7);
        ArrayList arrayList8 = new ArrayList();
        Iterator it10 = arrayList3.iterator();
        while (it10.hasNext()) {
            Object next5 = it10.next();
            if (((assistantMode.refactored.interfaces.c) next5).c() == EnumC1452f.b) {
                arrayList8.add(next5);
            }
        }
        ArrayList arrayList9 = new ArrayList(kotlin.collections.C.q(arrayList8, 10));
        Iterator it11 = arrayList8.iterator();
        while (it11.hasNext()) {
            arrayList9.add(Long.valueOf(((assistantMode.refactored.interfaces.c) it11.next()).b()));
        }
        HashSet elements2 = CollectionsKt.u0(arrayList9);
        Intrinsics.checkNotNullParameter(linkedHashSetZ0, "<this>");
        Intrinsics.checkNotNullParameter(elements2, "other");
        LinkedHashSet linkedHashSetZ02 = CollectionsKt.z0(linkedHashSetZ0);
        Intrinsics.checkNotNullParameter(linkedHashSetZ02, "<this>");
        Intrinsics.checkNotNullParameter(elements2, "elements");
        linkedHashSetZ02.removeAll(kotlin.collections.G.w(elements2));
        ArrayList arrayList10 = new ArrayList(kotlin.collections.C.q(arrayList4, 10));
        Iterator it12 = arrayList4.iterator();
        while (it12.hasNext()) {
            arrayList10.add(Long.valueOf(((assistantMode.refactored.interfaces.c) it12.next()).b()));
        }
        assistantMode.refactored.types.flashcards.h hVar = new assistantMode.refactored.types.flashcards.h(hashSetU02, linkedHashSetZ02, elements2, hashSetU03, CollectionsKt.u0(arrayList10), iIntValue2);
        if (!linkedHashSetZ02.isEmpty() || elements2.isEmpty()) {
            return hVar;
        }
        kotlin.collections.M m2 = kotlin.collections.M.a;
        return new assistantMode.refactored.types.flashcards.h(m2, elements2, m2, m2, m2, iIntValue2 + 1);
    }

    public static final ArrayList d(List list, HashSet hashSet) {
        ArrayList arrayList = new ArrayList();
        for (Object obj : list) {
            if (hashSet.contains(Long.valueOf(((assistantMode.refactored.interfaces.c) obj).b()))) {
                arrayList.add(obj);
            }
        }
        List listG0 = CollectionsKt.g0(CollectionsKt.n0(arrayList, kotlin.comparisons.a.a(assistantMode.refactored.types.flashcards.d.d, assistantMode.refactored.types.flashcards.d.e)));
        HashSet hashSet2 = new HashSet();
        ArrayList arrayList2 = new ArrayList();
        for (Object obj2 : listG0) {
            assistantMode.refactored.interfaces.c cVar = (assistantMode.refactored.interfaces.c) obj2;
            if (hashSet2.add(new Pair(Long.valueOf(cVar.b()), Long.valueOf(cVar.d())))) {
                arrayList2.add(obj2);
            }
        }
        return arrayList2;
    }
}
