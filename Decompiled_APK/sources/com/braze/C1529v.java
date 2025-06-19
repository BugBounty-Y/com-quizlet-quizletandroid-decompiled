package com.braze;

import androidx.glance.appwidget.protobuf.Z;
import com.braze.support.BrazeLogger;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* renamed from: com.braze.v, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1529v extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int a;
    public /* synthetic */ Object b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ Braze d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Function2 f;
    public final /* synthetic */ Function0 g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1529v(boolean z, Braze braze, Object obj, Function2 function2, Function0 function0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.c = z;
        this.d = braze;
        this.e = obj;
        this.f = function2;
        this.g = function0;
    }

    public static final String a(Function0 function0) {
        return "Early returning because the Braze instance isn't fully initialized. Always use Braze.getInstance(context) to get the latest Braze instance. Please report to Braze if the issue continues. > " + ((String) function0.invoke());
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1529v c1529v = new C1529v(this.c, this.d, this.e, this.f, this.g, hVar);
        c1529v.b = obj;
        return c1529v;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1529v) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.a;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            return obj;
        }
        Z.e(obj);
        kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.b;
        if (this.c && this.d.udm == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) c, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new com.braze.support.u(2, this.g), 6, (Object) null);
            return this.e;
        }
        Function2 function2 = this.f;
        this.a = 1;
        Object objInvoke = function2.invoke(c, this);
        return objInvoke == aVar ? aVar : objInvoke;
    }
}
