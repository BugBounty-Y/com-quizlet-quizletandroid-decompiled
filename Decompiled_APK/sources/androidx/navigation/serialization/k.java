package androidx.navigation.serialization;

import androidx.compose.runtime.snapshots.q;
import androidx.navigation.C1288j;
import androidx.navigation.C1290l;
import androidx.navigation.S;
import com.quizlet.assembly.compose.input.m;
import com.quizlet.eventlogger.features.explanations.ExplanationsLogger;
import com.quizlet.eventlogger.model.ExplanationsEventLog;
import com.quizlet.features.practicetest.detail.data.F;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.L;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.descriptors.SerialDescriptor;

/* loaded from: classes.dex */
public final /* synthetic */ class k implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ int c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ k(int i, int i2, Object obj, Object obj2, Object obj3) {
        this.a = i2;
        this.d = obj;
        this.c = i;
        this.e = obj2;
        this.b = obj3;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) throws ClassNotFoundException {
        Object obj2 = this.e;
        Object obj3 = this.b;
        int i = this.c;
        Object obj4 = this.d;
        switch (this.a) {
            case 0:
                C1290l navArgument = (C1290l) obj;
                Intrinsics.checkNotNullParameter(navArgument, "$this$navArgument");
                KSerializer kSerializer = (KSerializer) obj4;
                SerialDescriptor serialDescriptorI = kSerializer.getDescriptor().i(i);
                boolean zC = serialDescriptorI.c();
                L l = (L) obj2;
                S sA = d.a(serialDescriptorI, l);
                if (sA == null) {
                    String strA = serialDescriptorI.a();
                    String strA2 = kSerializer.getDescriptor().a();
                    l.getClass();
                    throw new IllegalArgumentException(d.g((String) obj3, strA, strA2, "{}"));
                }
                navArgument.b(sA);
                C1288j c1288j = navArgument.a;
                c1288j.a = zC;
                if (kSerializer.getDescriptor().j(i)) {
                    c1288j.c = true;
                }
                return Unit.a;
            case 1:
                ExplanationsEventLog.Payload createEvent = (ExplanationsEventLog.Payload) obj;
                int i2 = ExplanationsLogger.a;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.g(i, (String) obj3);
                ((ExplanationsLogger) obj4).getClass();
                ExplanationsLogger.e(createEvent, (ExplanationsLogger.EventData) obj2);
                return Unit.a;
            case 2:
                androidx.compose.foundation.lazy.g LazyColumn = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyColumn, "$this$LazyColumn");
                F f = (F) obj4;
                androidx.compose.foundation.lazy.g.p(LazyColumn, null, new androidx.compose.runtime.internal.d(true, 88840713, new m(24, f, (Function0) obj2)), 3);
                if (!f.g.isEmpty()) {
                    androidx.compose.foundation.lazy.g.p(LazyColumn, null, com.quizlet.features.practicetest.detail.b.a, 3);
                    androidx.compose.foundation.lazy.g.p(LazyColumn, null, new androidx.compose.runtime.internal.d(true, -2002009609, new m(25, f, (Function1) obj3)), 3);
                }
                androidx.compose.foundation.lazy.g.p(LazyColumn, null, com.quizlet.features.practicetest.detail.b.b, 3);
                List list = f.h;
                LazyColumn.q(list.size(), null, new com.quizlet.assembly.compose.menu.e(list, 8), new androidx.compose.runtime.internal.d(true, -1091073711, new com.quizlet.features.practicetest.detail.f(list, f, i)));
                return Unit.a;
            default:
                com.quizlet.assembly.compose.components.flashcards.b it2 = (com.quizlet.assembly.compose.components.flashcards.b) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                ((q) obj4).set(i, it2.a());
                ((com.quizlet.features.setpage.studypreview.g) obj2).C(new com.quizlet.features.setpage.studypreview.i((com.quizlet.features.setpage.studypreview.data.a) ((kotlinx.collections.immutable.e) obj3).get(i)));
                return Unit.a;
        }
    }

    public /* synthetic */ k(int i, ExplanationsLogger.EventData eventData, ExplanationsLogger explanationsLogger, String str) {
        this.a = 1;
        this.b = str;
        this.c = i;
        this.d = explanationsLogger;
        this.e = eventData;
    }

    public /* synthetic */ k(F f, Function0 function0, Function1 function1, int i) {
        this.a = 2;
        this.d = f;
        this.e = function0;
        this.b = function1;
        this.c = i;
    }
}
