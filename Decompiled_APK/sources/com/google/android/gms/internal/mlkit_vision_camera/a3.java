package com.google.android.gms.internal.mlkit_vision_camera;

import assistantMode.refactored.types.Task;
import com.google.android.gms.internal.mlkit_vision_barcode.X4;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class a3 {
    public static final /* synthetic */ int a = 0;

    public static final List a(List list, List list2, int i, Set set) {
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            arrayList.add(X4.c((assistantMode.enums.m) it2.next()));
        }
        kmppUtils.bitmasks.a[] aVarArr = (kmppUtils.bitmasks.a[]) arrayList.toArray(new assistantMode.enums.E[0]);
        com.airbnb.lottie.parser.l lVarD = n3.d((kmppUtils.bitmasks.a[]) Arrays.copyOf(aVarArr, aVarArr.length));
        ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(list2, 10));
        Iterator it3 = list2.iterator();
        while (it3.hasNext()) {
            arrayList2.add(X4.c((assistantMode.enums.m) it3.next()));
        }
        kmppUtils.bitmasks.a[] aVarArr2 = (kmppUtils.bitmasks.a[]) arrayList2.toArray(new assistantMode.enums.E[0]);
        com.airbnb.lottie.parser.l lVarD2 = n3.d((kmppUtils.bitmasks.a[]) Arrays.copyOf(aVarArr2, aVarArr2.length));
        kmppUtils.bitmasks.a[] aVarArr3 = (kmppUtils.bitmasks.a[]) set.toArray(new assistantMode.enums.k[0]);
        return kotlin.collections.B.j(new assistantMode.types.s(assistantMode.enums.z.n, lVarD.b), new assistantMode.types.s(assistantMode.enums.z.o, lVarD2.b), new assistantMode.types.s(assistantMode.enums.z.d, i), new assistantMode.types.s(assistantMode.enums.z.c, n3.d((kmppUtils.bitmasks.a[]) Arrays.copyOf(aVarArr3, aVarArr3.length)).b));
    }

    public static final Task b(LinkedHashMap linkedHashMap, List taskSequence) {
        Object next;
        Intrinsics.checkNotNullParameter(linkedHashMap, "<this>");
        Intrinsics.checkNotNullParameter(taskSequence, "taskSequence");
        Iterator it2 = taskSequence.iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            }
            next = it2.next();
            Object obj = linkedHashMap.get((Task) next);
            if (obj == null) {
                throw new IllegalArgumentException("Each Task must have an associated TaskProgressTracker before calculating the current Task index");
            }
            if (!((assistantMode.tasks.progress.b) obj).d()) {
                break;
            }
        }
        return (Task) next;
    }
}
