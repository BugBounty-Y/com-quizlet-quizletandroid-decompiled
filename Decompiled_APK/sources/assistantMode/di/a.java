package assistantMode.di;

import androidx.compose.ui.node.B;
import assistantMode.grading.l;
import com.quizlet.quizletandroid.ui.joincontenttofolder.j;
import com.quizlet.shared.usecase.studiableMetadata.h;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.r;
import org.koin.core.error.InstanceCreationException;

/* loaded from: classes.dex */
public final class a extends r implements Function2 {
    public static final a b = new a(2, 0);
    public static final a c = new a(2, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) throws Exception {
        Object objB = null;
        switch (this.a) {
            case 0:
                org.koin.core.scope.a aVar = (org.koin.core.scope.a) obj;
                grading.b bVar = (grading.b) aVar.a(null, B.q(aVar, "$this$factory", (org.koin.core.parameter.a) obj2, "it", grading.b.class), null);
                kmppUtils.time.a aVar2 = (kmppUtils.time.a) aVar.a(null, K.a(kmppUtils.time.a.class), null);
                try {
                    objB = aVar.b(null, K.a(com.quizlet.shared.usecase.grading.c.class), null);
                } catch (Exception e) {
                    if (!(e instanceof InstanceCreationException ? true : e instanceof IllegalStateException)) {
                        throw e;
                    }
                    ((j) aVar.b.c).d("|- Encountered " + K.a(e.getClass()).f() + ": Falling back to null!");
                }
                return new l(bVar, aVar2, (com.quizlet.shared.usecase.grading.c) objB);
            case 1:
                org.koin.core.scope.a factory = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it2 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(factory, "$this$factory");
                Intrinsics.checkNotNullParameter(it2, "it");
                try {
                    objB = factory.b(null, K.a(h.class), null);
                } catch (Exception e2) {
                    if (!(e2 instanceof InstanceCreationException ? true : e2 instanceof IllegalStateException)) {
                        throw e2;
                    }
                    ((j) factory.b.c).d("|- Encountered " + K.a(e2.getClass()).f() + ": Falling back to null!");
                }
                return new assistantMode.utils.studiableMetadata.b(0);
            case 2:
                org.koin.core.scope.a single = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it3 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(single, "$this$single");
                Intrinsics.checkNotNullParameter(it3, "it");
                grading.core.a[] aVarArr = grading.factories.a.a;
                return grading.factories.a.a();
            default:
                org.koin.core.scope.a single2 = (org.koin.core.scope.a) obj;
                org.koin.core.parameter.a it4 = (org.koin.core.parameter.a) obj2;
                Intrinsics.checkNotNullParameter(single2, "$this$single");
                Intrinsics.checkNotNullParameter(it4, "it");
                return new kmppUtils.time.b();
        }
    }
}
