package com.braze.storage;

import androidx.glance.appwidget.protobuf.Z;
import com.braze.AbstractC1484j;
import com.braze.support.BrazeLogger;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class u extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object a;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ v c;
    public final /* synthetic */ String d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public u(Function0 function0, v vVar, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.b = function0;
        this.c = vVar;
        this.d = str;
    }

    public static final String a(String str) {
        return AbstractC1484j.a("Failed to ", str);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        u uVar = new u(this.b, this.c, this.d, hVar);
        uVar.a = obj;
        return uVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((u) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.a;
        try {
            this.b.invoke();
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) c, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new D(this.d, 12), 4, (Object) null);
            this.c.a(e);
        }
        return Unit.a;
    }
}
