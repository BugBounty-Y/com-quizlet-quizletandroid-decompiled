package com.quizlet.eventlogger.features.learnonboarding;

import assistantMode.enums.y;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.quizlet.data.model.C4169u;
import com.quizlet.data.model.CreatedFolder;
import com.quizlet.eventlogger.features.learnonboarding.LearnOnboardingEventLog;
import com.quizlet.eventlogger.model.AndroidEventLog;
import com.quizlet.eventlogger.model.AndroidEventPayload;
import com.quizlet.features.infra.folder.menu.data.e;
import com.quizlet.features.infra.folder.menu.data.g;
import com.quizlet.features.infra.folder.menu.viewmodel.m;
import com.quizlet.generated.enums.A1;
import com.quizlet.shared.enums.h;
import com.quizlet.studiablemodels.StudiableMeteringData;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class b implements Function1 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ Object b;
    public final /* synthetic */ long c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ b(long j, StudiableMeteringData studiableMeteringData, String str, String str2) {
        this.b = str;
        this.c = j;
        this.d = str2;
        this.e = studiableMeteringData;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        A1 a1;
        long j;
        switch (this.a) {
            case 0:
                LearnOnboardingEventLog.Payload createEvent = (LearnOnboardingEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setSetId(Long.valueOf(this.c));
                createEvent.setGoalOptions((String) this.b);
                com.quizlet.studiablemodels.assistantMode.a aVar = (com.quizlet.studiablemodels.assistantMode.a) this.d;
                if (aVar != null) {
                    createEvent.setGoal(Integer.valueOf(aVar.ordinal()));
                }
                y yVar = (y) this.e;
                if (yVar != null) {
                    createEvent.setKnowledgeLevel(Integer.valueOf(yVar.ordinal()));
                }
                return Unit.a;
            case 1:
                AndroidEventLog logUserActionAndroidEvent = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent.setUserAction((String) this.b);
                logUserActionAndroidEvent.setSetId(Long.valueOf(this.c));
                logUserActionAndroidEvent.getPayload().setStudySessionId((String) this.d);
                AndroidEventPayload payload = logUserActionAndroidEvent.getPayload();
                StudiableMeteringData studiableMeteringData = (StudiableMeteringData) this.e;
                payload.setRemainingRounds(studiableMeteringData.e);
                logUserActionAndroidEvent.getPayload().setCompletedRounds(Integer.valueOf(studiableMeteringData.d));
                logUserActionAndroidEvent.getPayload().setAssignedRounds(studiableMeteringData.c);
                AndroidEventPayload payload2 = logUserActionAndroidEvent.getPayload();
                h hVar = studiableMeteringData.a;
                Intrinsics.checkNotNullParameter(hVar, "<this>");
                int iOrdinal = hVar.ordinal();
                if (iOrdinal == 0) {
                    a1 = null;
                } else if (iOrdinal == 1) {
                    a1 = A1.LEARNING_ASSISTANT;
                } else {
                    if (iOrdinal != 2) {
                        throw new NoWhenBranchMatchedException();
                    }
                    a1 = A1.TEST;
                }
                payload2.setMode(a1 != null ? Integer.valueOf(a1.a()) : null);
                return Unit.a;
            default:
                com.quizlet.features.infra.folder.menu.screenstates.c cVar = (com.quizlet.features.infra.folder.menu.screenstates.c) obj;
                C4169u c4169u = (C4169u) this.d;
                m mVar = (m) this.b;
                com.quizlet.features.infra.folder.menu.data.b bVarX = mVar.x(c4169u);
                ArrayList arrayListY0 = CollectionsKt.y0(cVar.a);
                Iterator it2 = arrayListY0.iterator();
                int i = 0;
                while (true) {
                    boolean zHasNext = it2.hasNext();
                    j = this.c;
                    if (!zHasNext) {
                        i = -1;
                    } else if (((g) it2.next()).getId() != j) {
                        i++;
                    }
                }
                arrayListY0.set(i, bVarX);
                List<CreatedFolder> list = (List) this.e;
                ArrayList arrayList = new ArrayList(C.q(list, 10));
                for (CreatedFolder createdFolder : list) {
                    arrayList.add(new e(j, createdFolder.a(), createdFolder.g(), false));
                }
                LinkedHashSet linkedHashSetZ0 = CollectionsKt.z0(cVar.b);
                mVar.m(linkedHashSetZ0, arrayList);
                kotlinx.collections.immutable.e items = AbstractC3409x1.k(arrayListY0);
                kotlinx.collections.immutable.c selected = AbstractC3409x1.j(linkedHashSetZ0);
                boolean z = !linkedHashSetZ0.equals(m.t(cVar.a));
                Intrinsics.checkNotNullParameter(items, "items");
                Intrinsics.checkNotNullParameter(selected, "selected");
                return new com.quizlet.features.infra.folder.menu.screenstates.c(items, selected, z);
        }
    }

    public /* synthetic */ b(long j, String str, com.quizlet.studiablemodels.assistantMode.a aVar, y yVar) {
        this.c = j;
        this.b = str;
        this.d = aVar;
        this.e = yVar;
    }

    public /* synthetic */ b(m mVar, C4169u c4169u, List list, long j) {
        this.b = mVar;
        this.d = c4169u;
        this.e = list;
        this.c = j;
    }
}
