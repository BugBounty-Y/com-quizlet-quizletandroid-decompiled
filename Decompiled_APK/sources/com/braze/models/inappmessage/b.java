package com.braze.models.inappmessage;

import androidx.glance.appwidget.protobuf.Z;
import com.braze.AbstractC1484j;
import com.braze.managers.C1500m;
import com.braze.managers.c0;
import com.braze.support.BrazeLogger;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.text.StringsKt;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object a;
    public final /* synthetic */ String b;
    public final /* synthetic */ String c;
    public final /* synthetic */ c0 d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(String str, String str2, c0 c0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.b = str;
        this.c = str2;
        this.d = c0Var;
    }

    public static final String a(String str) {
        return AbstractC1484j.a("Logging click on in-app message with button id: ", str);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        b bVar = new b(this.b, this.c, this.d, hVar);
        bVar.a = obj;
        return bVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        C c = (C) this.a;
        String str = this.b;
        if (str == null || StringsKt.O(str)) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) c, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new com.braze.models.j(27), 6, (Object) null);
            com.braze.models.i iVarO = com.braze.models.outgoing.event.b.g.o(this.c);
            if (iVarO != null) {
                ((C1500m) this.d).a(iVarO);
            }
        } else {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) c, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new com.braze.managers.C(this.b, 15), 6, (Object) null);
            com.braze.models.i iVarI = com.braze.models.outgoing.event.b.g.i(this.c, this.b);
            if (iVarI != null) {
                ((C1500m) this.d).a(iVarI);
            }
        }
        return Unit.a;
    }

    public static final String a() {
        return "Logging click on in-app message";
    }
}
