package com.quizlet.security.qltj.core;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.local.datastore.preferences.B;
import com.quizlet.local.datastore.preferences.J;
import java.net.URI;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ String k;
    public final /* synthetic */ URI l;
    public final /* synthetic */ c m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(String str, URI uri, c cVar, h hVar) {
        super(2, hVar);
        this.k = str;
        this.l = uri;
        this.m = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        String str = this.k;
        c cVar = this.m;
        if (i == 0) {
            Z.e(obj);
            String string = this.l.toString();
            Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
            B b = new B(str, string);
            J j = cVar.a;
            this.j = 1;
            if (j.d(b, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        cVar.getClass();
        cVar.c = c.a(str);
        cVar.d++;
        return Unit.a;
    }
}
