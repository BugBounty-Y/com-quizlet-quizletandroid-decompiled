package assistantMode.tasks.progress;

import androidx.compose.runtime.internal.j;
import assistantMode.enums.k;
import assistantMode.refactored.types.Task;
import assistantMode.refactored.types.TaskQuestionTypeProgress;
import assistantMode.types.C1455b;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import kotlin.collections.C;
import kotlin.collections.G;
import kotlin.collections.U;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b {
    public final Task a;
    public final Set b;
    public final LinkedHashMap c;
    public final j d;

    public b(Task task, Set studiableItemIds, j questionTypeApplicability) {
        Intrinsics.checkNotNullParameter(task, "task");
        Intrinsics.checkNotNullParameter(studiableItemIds, "studiableItemIds");
        Intrinsics.checkNotNullParameter(questionTypeApplicability, "questionTypeApplicability");
        this.a = task;
        this.b = studiableItemIds;
        List list = task.a;
        int iA = U.a(C.q(list, 10));
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA < 16 ? 16 : iA);
        for (Object obj : list) {
            linkedHashMap.put(obj, new a(studiableItemIds, task, (k) obj));
        }
        this.c = linkedHashMap;
        this.d = questionTypeApplicability;
    }

    public final void a(C1455b answer, k desiredQuestionType) {
        Intrinsics.checkNotNullParameter(answer, "answer");
        Intrinsics.checkNotNullParameter(desiredQuestionType, "desiredQuestionType");
        a aVar = (a) V.d(desiredQuestionType, this.c);
        aVar.getClass();
        Intrinsics.checkNotNullParameter(answer, "answer");
        Task task = aVar.b;
        Intrinsics.checkNotNullParameter(task, "task");
        if (answer != null) {
            List list = task.a;
            k kVar = answer.d;
            boolean zContains = list.contains(kVar);
            List list2 = task.a;
            boolean z = zContains || list2.contains(W4.c(kVar));
            ArrayList arrayList = new ArrayList();
            Iterator it2 = list2.iterator();
            while (it2.hasNext()) {
                G.u(arrayList, W4.a((k) it2.next()));
            }
            boolean zContains2 = arrayList.contains(kVar);
            if (z || zContains2) {
                LinkedHashSet linkedHashSet = aVar.f;
                long j = answer.e;
                linkedHashSet.remove(Long.valueOf(j));
                LinkedHashSet linkedHashSet2 = aVar.e;
                linkedHashSet2.remove(Long.valueOf(j));
                if (answer.a) {
                    aVar.d.add(Long.valueOf(j));
                } else {
                    linkedHashSet2.add(Long.valueOf(j));
                }
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:10:0x0026, code lost:
    
        r5 = r5.b;
     */
    /* JADX WARN: Removed duplicated region for block: B:47:0x00ca  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final assistantMode.refactored.types.TaskProgress b() {
        /*
            Method dump skipped, instructions count: 458
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: assistantMode.tasks.progress.b.b():assistantMode.refactored.types.TaskProgress");
    }

    public final LinkedHashMap c() {
        List list = this.a.a;
        int iA = U.a(C.q(list, 10));
        if (iA < 16) {
            iA = 16;
        }
        LinkedHashMap linkedHashMap = new LinkedHashMap(iA);
        for (Object obj : list) {
            a aVar = (a) V.d((k) obj, this.c);
            Set set = aVar.a;
            linkedHashMap.put(obj, set.isEmpty() ? assistantMode.a.c : new TaskQuestionTypeProgress(aVar.d.size(), set.size()));
        }
        return linkedHashMap;
    }

    public final boolean d() {
        List list = this.a.a;
        if (list != null && list.isEmpty()) {
            return true;
        }
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            a aVar = (a) V.d((k) it2.next(), this.c);
            Set set = aVar.a;
            TaskQuestionTypeProgress taskQuestionTypeProgress = set.isEmpty() ? assistantMode.a.c : new TaskQuestionTypeProgress(aVar.d.size(), set.size());
            if (taskQuestionTypeProgress.a != taskQuestionTypeProgress.b) {
                return false;
            }
        }
        return true;
    }
}
