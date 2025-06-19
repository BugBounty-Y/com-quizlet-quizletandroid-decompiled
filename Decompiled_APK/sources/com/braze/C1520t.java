package com.braze;

import androidx.glance.appwidget.protobuf.Z;
import com.braze.support.BrazeLogger;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* renamed from: com.braze.t, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1520t extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ Braze d;
    public final /* synthetic */ Function0 e;
    public final /* synthetic */ Function0 f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1520t(boolean z, boolean z2, Braze braze, Function0 function0, Function0 function02, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.b = z;
        this.c = z2;
        this.d = braze;
        this.e = function0;
        this.f = function02;
    }

    public static final String a(Function0 function0) {
        return "Early returning because the Braze instance isn't fully initialized. Always use Braze.getInstance(context) to get the latest Braze instance. Please report to Braze if the issue continues. > " + ((String) function0.invoke());
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1520t c1520t = new C1520t(this.b, this.c, this.d, this.e, this.f, hVar);
        c1520t.a = obj;
        return c1520t;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1520t) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.a;
        if (this.b && Braze.Companion.isDisabled()) {
            return Unit.a;
        }
        if (this.c && this.d.udm == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) c, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new com.braze.support.u(1, this.f), 6, (Object) null);
            return Unit.a;
        }
        this.e.invoke();
        return Unit.a;
    }
}
