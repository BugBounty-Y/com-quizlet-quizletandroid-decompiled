package androidx.compose.ui.input.pointer;

import android.content.Context;
import androidx.compose.ui.graphics.C0861v;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.Q;

/* loaded from: classes.dex */
public final class u implements Function1 {
    public final /* synthetic */ int a;
    public Object b;

    public /* synthetic */ u() {
        this.a = 0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                boolean zBooleanValue = ((Boolean) obj).booleanValue();
                r rVar = (r) this.b;
                if (rVar != null) {
                    rVar.d = zBooleanValue;
                }
                break;
            case 1:
                List list = (List) obj;
                Intrinsics.checkNotNullParameter(list, "list");
                Boolean bool = (Boolean) list.get(0);
                com.quizlet.explanations.questiondetail.data.e eVar = (com.quizlet.explanations.questiondetail.data.e) list.get(1);
                Intrinsics.d(bool);
                boolean zBooleanValue2 = bool.booleanValue();
                Intrinsics.d(eVar);
                ((com.quizlet.explanations.questiondetail.viewmodel.f) this.b).getClass();
                if (zBooleanValue2 && !eVar.a.isEmpty()) {
                    break;
                } else {
                    break;
                }
                break;
            case 2:
                Intrinsics.checkNotNullParameter((Context) obj, "<unused var>");
                break;
            case 3:
                long j = ((C0861v) obj).a;
                com.quizlet.learn.viewmodel.k kVar = (com.quizlet.learn.viewmodel.k) this.b;
                if (kVar != null) {
                    kVar.invoke();
                }
                break;
            case 4:
                ((Q) this.b).dispose();
                break;
            case 5:
                ((okhttp3.internal.connection.g) this.b).cancel();
                break;
            default:
                ((io.reactivex.rxjava3.disposables.b) this.b).dispose();
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ u(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }
}
