package androidx.navigation.serialization;

import androidx.compose.ui.node.B;
import androidx.navigation.AbstractC1285g;
import androidx.navigation.S;
import com.quizlet.features.questiontypes.written.ui.m;
import com.quizlet.features.questiontypes.written.ui.o;
import com.quizlet.features.setpage.termlist.TermListComposeFragment;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;

/* loaded from: classes.dex */
public final /* synthetic */ class i implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ i(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        com.quizlet.features.questiontypes.written.data.a aVar;
        Object obj4 = this.b;
        switch (this.a) {
            case 0:
                int iIntValue = ((Integer) obj).intValue();
                String name = (String) obj2;
                S type = (S) obj3;
                Intrinsics.checkNotNullParameter(name, "argName");
                Intrinsics.checkNotNullParameter(type, "navType");
                com.quizlet.data.repository.progress.b bVar = (com.quizlet.data.repository.progress.b) obj4;
                Intrinsics.checkNotNullParameter(name, "name");
                Intrinsics.checkNotNullParameter(type, "type");
                int iOrdinal = (((type instanceof AbstractC1285g) || ((KSerializer) bVar.a).getDescriptor().j(iIntValue)) ? f.b : f.a).ordinal();
                if (iOrdinal == 0) {
                    bVar.c = ((String) bVar.c) + '/' + B.h("{", name, '}');
                } else {
                    if (iOrdinal != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                    bVar.a(name, "{" + name + '}');
                }
                return Unit.a;
            case 1:
                String response = (String) obj;
                Boolean bool = (Boolean) obj2;
                bool.booleanValue();
                o state = (o) obj3;
                Intrinsics.checkNotNullParameter(response, "response");
                Intrinsics.checkNotNullParameter(state, "state");
                if (Intrinsics.b(state, m.b)) {
                    aVar = com.quizlet.features.questiontypes.written.data.a.c;
                } else if (Intrinsics.b(state, com.quizlet.features.questiontypes.written.ui.l.b)) {
                    aVar = com.quizlet.features.questiontypes.written.data.a.d;
                } else if (Intrinsics.b(state, com.quizlet.features.questiontypes.written.ui.k.b)) {
                    aVar = com.quizlet.features.questiontypes.written.data.a.b;
                } else {
                    if (!Intrinsics.b(state, com.quizlet.features.questiontypes.written.ui.j.a)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    aVar = null;
                }
                ((kotlin.jvm.functions.c) obj4).invoke(response, bool, aVar);
                return Unit.a;
            case 2:
                String response2 = (String) obj;
                Intrinsics.checkNotNullParameter(response2, "response");
                ((com.quizlet.features.questiontypes.written.o) ((com.quizlet.features.questiontypes.written.a) obj4)).F(new com.quizlet.features.questiontypes.written.e(response2, ((Boolean) obj2).booleanValue(), (com.quizlet.features.questiontypes.written.data.a) obj3));
                return Unit.a;
            case 3:
                long jLongValue = ((Long) obj).longValue();
                boolean zBooleanValue = ((Boolean) obj2).booleanValue();
                String str = TermListComposeFragment.m;
                ((TermListComposeFragment) obj4).U().B(new com.quizlet.features.setpage.termlist.data.f((String) obj3, jLongValue, !zBooleanValue));
                return Unit.a;
            case 4:
                ((Integer) obj3).getClass();
                Intrinsics.checkNotNullParameter((String) obj, "<unused var>");
                Intrinsics.checkNotNullParameter((String) obj2, "<unused var>");
                ((com.quizlet.features.questionnaire.screens.c) obj4).invoke();
                return Unit.a;
            case 5:
                ((Long) obj).getClass();
                ((Integer) obj3).getClass();
                Intrinsics.checkNotNullParameter((String) obj2, "<unused var>");
                ((com.quizlet.features.questionnaire.screens.c) obj4).invoke();
                return Unit.a;
            case 6:
                ((Long) obj).getClass();
                ((Integer) obj2).getClass();
                ((Boolean) obj3).getClass();
                ((com.quizlet.features.questionnaire.screens.c) obj4).invoke();
                return Unit.a;
            case 7:
                ((com.quizlet.quizletandroid.ui.subject.f) obj4).invoke((Throwable) obj);
                return Unit.a;
            default:
                ((kotlinx.coroutines.sync.h) obj4).c();
                return Unit.a;
        }
    }
}
