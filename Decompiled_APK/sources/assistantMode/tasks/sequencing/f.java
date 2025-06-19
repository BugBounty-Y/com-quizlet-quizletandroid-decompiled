package assistantMode.tasks.sequencing;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class f extends r implements Function0 {
    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        com.quizlet.data.repository.login.a aVar = com.quizlet.shared.di.a.a;
        if (aVar != null) {
            return ((org.koin.core.registry.a) aVar.a).b.a(null, K.a(kotlin.random.e.class), null);
        }
        throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
    }
}
