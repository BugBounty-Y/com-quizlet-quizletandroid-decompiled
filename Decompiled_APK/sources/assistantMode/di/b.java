package assistantMode.di;

import androidx.compose.ui.text.C0981a;
import assistantMode.grading.i;
import assistantMode.grading.l;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3418z2;
import com.quizlet.shared.usecase.di.e;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import org.koin.core.definition.d;

/* loaded from: classes.dex */
public final class b extends r implements Function1 {
    public static final b b = new b(1, 0);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ b(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        int i = 2;
        switch (this.a) {
            case 0:
                org.koin.core.module.a module = (org.koin.core.module.a) obj;
                Intrinsics.checkNotNullParameter(module, "$this$module");
                module.a(e.a);
                grading.core.a[] aVarArr = grading.factories.a.a;
                a aVar = new a(i, i);
                org.koin.core.qualifier.a aVar2 = org.koin.core.registry.a.c;
                org.koin.core.definition.c cVar = org.koin.core.definition.c.a;
                K k = K.a;
                org.koin.core.definition.b beanDefinition = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(grading.a.class), null, aVar, cVar, k);
                Intrinsics.checkNotNullParameter(beanDefinition, "beanDefinition");
                org.koin.core.instance.c cVar2 = new org.koin.core.instance.c(beanDefinition);
                module.b(cVar2);
                d dVar = new d(module, cVar2);
                Intrinsics.checkNotNullParameter(dVar, "<this>");
                AbstractC3418z2.a(dVar, kotlin.jvm.internal.K.a(grading.b.class));
                org.koin.core.definition.b beanDefinition2 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(kmppUtils.time.b.class), null, new a(i, 3), cVar, k);
                Intrinsics.checkNotNullParameter(beanDefinition2, "beanDefinition");
                org.koin.core.instance.c cVar3 = new org.koin.core.instance.c(beanDefinition2);
                module.b(cVar3);
                d dVar2 = new d(module, cVar3);
                Intrinsics.checkNotNullParameter(dVar2, "<this>");
                AbstractC3418z2.a(dVar2, kotlin.jvm.internal.K.a(kmppUtils.time.a.class));
                a aVar3 = a.b;
                org.koin.core.definition.c cVar4 = org.koin.core.definition.c.b;
                org.koin.core.definition.b beanDefinition3 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(l.class), null, aVar3, cVar4, k);
                Intrinsics.checkNotNullParameter(beanDefinition3, "beanDefinition");
                org.koin.core.instance.a aVar4 = new org.koin.core.instance.a(beanDefinition3);
                module.b(aVar4);
                AbstractC3418z2.a(new d(module, aVar4), kotlin.jvm.internal.K.a(i.class));
                org.koin.core.definition.b beanDefinition4 = new org.koin.core.definition.b(aVar2, kotlin.jvm.internal.K.a(assistantMode.utils.studiableMetadata.b.class), null, a.c, cVar4, k);
                Intrinsics.checkNotNullParameter(beanDefinition4, "beanDefinition");
                org.koin.core.instance.a aVar5 = new org.koin.core.instance.a(beanDefinition4);
                module.b(aVar5);
                AbstractC3418z2.a(new d(module, aVar5), kotlin.jvm.internal.K.a(assistantMode.utils.studiableMetadata.a.class));
                break;
            default:
                org.koin.core.module.a module2 = (org.koin.core.module.a) obj;
                Intrinsics.checkNotNullParameter(module2, "$this$module");
                C0981a c0981a = new C0981a(kotlin.random.e.a, 5);
                org.koin.core.definition.b beanDefinition5 = new org.koin.core.definition.b(org.koin.core.registry.a.c, kotlin.jvm.internal.K.a(kotlin.random.e.class), null, c0981a, org.koin.core.definition.c.a, K.a);
                Intrinsics.checkNotNullParameter(beanDefinition5, "beanDefinition");
                org.koin.core.instance.c cVar5 = new org.koin.core.instance.c(beanDefinition5);
                module2.b(cVar5);
                AbstractC3418z2.a(new d(module2, cVar5), kotlin.jvm.internal.K.a(kotlin.random.e.class));
                break;
        }
        return Unit.a;
    }
}
