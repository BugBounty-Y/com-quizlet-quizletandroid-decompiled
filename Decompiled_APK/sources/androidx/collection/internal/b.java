package androidx.collection.internal;

import androidx.compose.runtime.internal.j;
import androidx.constraintlayout.core.e;
import assistantMode.types.C1455b;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.collections.CollectionsKt;
import kotlin.collections.U;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b {
    public final LinkedHashMap a;

    public b(ArrayList answers, j questionTypeApplicability, List enabledPromptSides, List enabledAnswerSides) {
        Intrinsics.checkNotNullParameter(answers, "answers");
        Intrinsics.checkNotNullParameter(questionTypeApplicability, "questionTypeApplicability");
        Intrinsics.checkNotNullParameter(enabledPromptSides, "enabledPromptSides");
        Intrinsics.checkNotNullParameter(enabledAnswerSides, "enabledAnswerSides");
        List listN0 = CollectionsKt.n0(answers, new e(5));
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        for (Object obj : listN0) {
            Long lValueOf = Long.valueOf(((C1455b) obj).e);
            Object arrayList = linkedHashMap.get(lValueOf);
            if (arrayList == null) {
                arrayList = new ArrayList();
                linkedHashMap.put(lValueOf, arrayList);
            }
            ((List) arrayList).add(obj);
        }
        LinkedHashMap linkedHashMap2 = new LinkedHashMap(U.a(linkedHashMap.size()));
        for (Map.Entry entry : linkedHashMap.entrySet()) {
            linkedHashMap2.put(entry.getKey(), CollectionsKt.y0((Collection) entry.getValue()));
        }
        this.a = V.m(linkedHashMap2);
    }

    public b() {
        this.a = new LinkedHashMap(0, 0.75f, true);
    }
}
