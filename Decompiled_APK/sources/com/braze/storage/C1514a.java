package com.braze.storage;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.braze.storage.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1514a extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlinx.coroutines.sync.e a;
    public int b;
    public final /* synthetic */ AbstractC1515b c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1514a(AbstractC1515b abstractC1515b, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.c = abstractC1515b;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1514a(this.c, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return new C1514a(this.c, (kotlin.coroutines.h) obj2).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object obj2;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.b;
        if (i == 0) {
            Z.e(obj);
            kotlinx.coroutines.sync.e eVar = this.c.a;
            this.a = eVar;
            this.b = 1;
            if (((kotlinx.coroutines.sync.h) eVar).a(this) == aVar) {
                return aVar;
            }
            obj2 = eVar;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            obj2 = this.a;
            Z.e(obj);
        }
        try {
            return Unit.a;
        } finally {
            ((kotlinx.coroutines.sync.h) obj2).c();
        }
    }
}
