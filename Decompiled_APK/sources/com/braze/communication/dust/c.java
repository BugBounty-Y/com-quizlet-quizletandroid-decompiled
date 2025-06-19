package com.braze.communication.dust;

import androidx.glance.appwidget.protobuf.Z;
import com.braze.Y;
import com.braze.support.BrazeLogger;
import java.io.BufferedReader;
import java.io.IOException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.channels.t;
import kotlinx.coroutines.channels.u;

/* loaded from: classes.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int a;
    public /* synthetic */ Object b;
    public final /* synthetic */ BufferedReader c;
    public final /* synthetic */ u d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(BufferedReader bufferedReader, u uVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.c = bufferedReader;
        this.d = uVar;
    }

    public static final String a() {
        return "Caught unexpected exception in stream producer";
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        c cVar = new c(this.c, this.d, hVar);
        cVar.b = obj;
        return cVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [int, kotlinx.coroutines.C] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws IOException {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        ?? r1 = this.a;
        try {
            if (r1 == 0) {
                Z.e(obj);
                C c = (C) this.b;
                String line = this.c.readLine();
                if (line == null) {
                    return Unit.a;
                }
                u uVar = this.d;
                this.b = c;
                this.a = 1;
                if (((t) uVar).d.s(line, this) == aVar) {
                    return aVar;
                }
            } else {
                if (r1 != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
        } catch (Exception e) {
            if (E.x(r1)) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, h.b, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new Y(2), 8, (Object) null);
            } else {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, h.b, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new i(0, e), 14, (Object) null);
            }
        }
        return Unit.a;
    }

    public static final String a(Exception exc) {
        return "Stream producer job cancelled " + exc;
    }
}
