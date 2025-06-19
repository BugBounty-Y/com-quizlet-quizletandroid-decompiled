package androidx.compose.ui.scrollcapture;

import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t;
import com.quizlet.search.viewmodels.p;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4942a;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class k extends C4942a implements Function1 {
    public final /* synthetic */ int h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ k(int i, Object obj, Class cls, String str, String str2, int i2, int i3) {
        super(i, i2, cls, obj, str, str2);
        this.h = i3;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.h) {
            case 0:
                ((androidx.compose.runtime.collection.b) this.a).b((m) obj);
                break;
            case 1:
                com.quizlet.uicommon.ui.common.util.d p0 = (com.quizlet.uicommon.ui.common.util.d) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                ((t) this.a).B(p0, K.a);
                break;
            case 2:
                com.quizlet.uicommon.ui.common.util.d p02 = (com.quizlet.uicommon.ui.common.util.d) obj;
                Intrinsics.checkNotNullParameter(p02, "p0");
                ((t) this.a).B(p02, K.a);
                break;
            case 3:
                com.quizlet.uicommon.ui.common.util.d p03 = (com.quizlet.uicommon.ui.common.util.d) obj;
                Intrinsics.checkNotNullParameter(p03, "p0");
                ((t) this.a).B(p03, K.a);
                break;
            case 4:
                com.quizlet.ui.models.content.carditem.f model = (com.quizlet.ui.models.content.carditem.f) obj;
                Intrinsics.checkNotNullParameter(model, "p0");
                com.quizlet.quizletandroid.ui.subject.viewmodel.m mVar = (com.quizlet.quizletandroid.ui.subject.viewmodel.m) this.a;
                mVar.getClass();
                Intrinsics.checkNotNullParameter(model, "model");
                mVar.D();
                long j = model.a;
                com.quizlet.data.interactor.achievements.f fVar = mVar.e;
                fVar.getClass();
                EventLoggerExt.c((EventLogger) fVar.b, new com.braze.requests.framework.m(18, j));
                mVar.g.j(new com.quizlet.quizletandroid.ui.subject.viewmodel.b(model.a));
                break;
            case 5:
                String p04 = (String) obj;
                Intrinsics.checkNotNullParameter(p04, "p0");
                ((p) this.a).B(p04, true);
                break;
            default:
                Object objC = ((io.ktor.util.pipeline.e) this.a).c((kotlin.coroutines.h) obj);
                if (objC != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
        }
        return Unit.a;
    }
}
