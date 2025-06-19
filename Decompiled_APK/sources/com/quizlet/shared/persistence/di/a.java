package com.quizlet.shared.persistence.di;

import com.google.android.gms.internal.mlkit_vision_camera.A2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3418z2;
import com.quizlet.shared.persistence.studiableMetadata.e;
import com.quizlet.shared.persistence.studiableMetadata.f;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import org.koin.core.definition.d;

/* loaded from: classes3.dex */
public final class a extends r implements Function1 {
    public static final a b = new a(1, 0);
    public static final a c = new a(1, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                org.koin.core.module.a module = (org.koin.core.module.a) obj;
                Intrinsics.checkNotNullParameter(module, "$this$module");
                module.a(A2.b(c));
                break;
            default:
                org.koin.core.module.a module2 = (org.koin.core.module.a) obj;
                Intrinsics.checkNotNullParameter(module2, "$this$module");
                module2.a(com.quizlet.shared.models.api.di.c.a);
                int i = 2;
                c cVar = new c(i, 1);
                org.koin.core.qualifier.a aVar = org.koin.core.registry.a.c;
                org.koin.core.definition.c cVar2 = org.koin.core.definition.c.a;
                K k = K.a;
                org.koin.core.definition.b beanDefinition = new org.koin.core.definition.b(aVar, kotlin.jvm.internal.K.a(com.quizlet.shared.persistence.db.persistencedatabase.c.class), null, cVar, cVar2, k);
                Intrinsics.checkNotNullParameter(beanDefinition, "beanDefinition");
                org.koin.core.instance.c cVar3 = new org.koin.core.instance.c(beanDefinition);
                module2.b(cVar3);
                Intrinsics.checkNotNullParameter(new d(module2, cVar3), "<this>");
                org.koin.core.definition.b beanDefinition2 = new org.koin.core.definition.b(aVar, kotlin.jvm.internal.K.a(e.class), null, new c(i, 2), cVar2, k);
                Intrinsics.checkNotNullParameter(beanDefinition2, "beanDefinition");
                org.koin.core.instance.c cVar4 = new org.koin.core.instance.c(beanDefinition2);
                module2.b(cVar4);
                Intrinsics.checkNotNullParameter(new d(module2, cVar4), "<this>");
                org.koin.core.definition.b beanDefinition3 = new org.koin.core.definition.b(aVar, kotlin.jvm.internal.K.a(f.class), null, c.b, cVar2, k);
                Intrinsics.checkNotNullParameter(beanDefinition3, "beanDefinition");
                org.koin.core.instance.c cVar5 = new org.koin.core.instance.c(beanDefinition3);
                module2.b(cVar5);
                AbstractC3418z2.a(new d(module2, cVar5), kotlin.jvm.internal.K.a(f.class));
                break;
        }
        return Unit.a;
    }
}
