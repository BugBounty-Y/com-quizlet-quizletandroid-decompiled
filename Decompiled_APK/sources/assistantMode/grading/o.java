package assistantMode.grading;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class o extends r implements Function0 {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ o(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                com.quizlet.data.repository.login.a aVar = com.quizlet.shared.di.a.a;
                if (aVar != null) {
                    return ((org.koin.core.registry.a) aVar.a).b.a(null, K.a(i.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
            case 1:
                com.quizlet.data.repository.login.a aVar2 = com.quizlet.shared.di.a.a;
                if (aVar2 != null) {
                    return ((org.koin.core.registry.a) aVar2.a).b.a(null, K.a(kotlin.random.e.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
            case 2:
                com.quizlet.data.repository.login.a aVar3 = com.quizlet.shared.di.a.a;
                if (aVar3 != null) {
                    return ((org.koin.core.registry.a) aVar3.a).b.a(null, K.a(kotlin.random.e.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
            case 3:
                com.quizlet.data.repository.login.a aVar4 = com.quizlet.shared.di.a.a;
                if (aVar4 != null) {
                    return ((org.koin.core.registry.a) aVar4.a).b.a(null, K.a(kotlin.random.e.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
            case 4:
                com.quizlet.data.repository.login.a aVar5 = com.quizlet.shared.di.a.a;
                if (aVar5 != null) {
                    return ((org.koin.core.registry.a) aVar5.a).b.a(null, K.a(kotlin.random.e.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
            case 5:
                com.quizlet.data.repository.login.a aVar6 = com.quizlet.shared.di.a.a;
                if (aVar6 != null) {
                    return ((org.koin.core.registry.a) aVar6.a).b.a(null, K.a(assistantMode.utils.studiableMetadata.b.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
            default:
                com.quizlet.data.repository.login.a aVar7 = com.quizlet.shared.di.a.a;
                if (aVar7 != null) {
                    return ((org.koin.core.registry.a) aVar7.a).b.a(null, K.a(kotlin.random.e.class), null);
                }
                throw new IllegalArgumentException("KmpKoinContext is null: have you called KmpKoinContext.startKoin yet?");
        }
    }
}
