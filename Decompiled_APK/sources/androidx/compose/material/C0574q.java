package androidx.compose.material;

import android.os.Bundle;
import androidx.compose.foundation.gestures.C0337m;
import androidx.datastore.core.InterfaceC1076h;
import androidx.glance.appwidget.C1164d;
import androidx.glance.appwidget.C1166e;
import androidx.glance.appwidget.C1182m;
import com.google.android.gms.internal.mlkit_vision_barcode.Z6;
import io.ktor.client.plugins.AbstractC4863j;
import io.ktor.client.plugins.AbstractC4866m;
import io.ktor.client.plugins.C4860g;
import io.ktor.client.plugins.C4861h;
import io.ktor.client.plugins.C4864k;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.InterfaceC5002j;
import kotlinx.coroutines.y0;

/* renamed from: androidx.compose.material.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0574q extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public final /* synthetic */ int j;
    public int k;
    public /* synthetic */ Object l;
    public /* synthetic */ Object m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0574q(int i, int i2, kotlin.coroutines.h hVar) {
        super(i, hVar);
        this.j = i2;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        switch (this.j) {
            case 0:
                androidx.compose.foundation.gestures.V v = (androidx.compose.foundation.gestures.V) this.l;
                return new C0574q((r) this.m, v, (kotlin.coroutines.h) obj3, 0).invokeSuspend(Unit.a);
            case 1:
                androidx.compose.foundation.gestures.V v2 = (androidx.compose.foundation.gestures.V) this.l;
                return new C0574q((r) this.m, v2, (kotlin.coroutines.h) obj3, 1).invokeSuspend(Unit.a);
            case 2:
                C0574q c0574q = new C0574q((Bundle) this.l, (kotlin.coroutines.h) obj3, 2);
                c0574q.m = (C1182m) obj2;
                return c0574q.invokeSuspend(Unit.a);
            case 3:
                C0574q c0574q2 = new C0574q((String) this.l, (kotlin.coroutines.h) obj3, 3);
                c0574q2.m = (C1182m) obj2;
                return c0574q2.invokeSuspend(Unit.a);
            case 4:
                C0574q c0574q3 = new C0574q(3, 4, (kotlin.coroutines.h) obj3);
                c0574q3.m = (androidx.paging.I) obj;
                c0574q3.l = (androidx.paging.I) obj2;
                return c0574q3.invokeSuspend(Unit.a);
            case 5:
                C0574q c0574q4 = new C0574q(3, 5, (kotlin.coroutines.h) obj3);
                c0574q4.m = (InterfaceC5002j) obj;
                c0574q4.l = (Object[]) obj2;
                return c0574q4.invokeSuspend(Unit.a);
            case 6:
                C0574q c0574q5 = new C0574q((com.quizlet.local.datastore.preferences.J) this.l, (kotlin.coroutines.h) obj3, 6);
                c0574q5.m = (InterfaceC5002j) obj;
                return c0574q5.invokeSuspend(Unit.a);
            case 7:
                C0574q c0574q6 = new C0574q((io.ktor.client.c) this.l, (kotlin.coroutines.h) obj3, 7);
                c0574q6.m = (io.ktor.util.pipeline.e) obj;
                return c0574q6.invokeSuspend(Unit.a);
            case 8:
                C0574q c0574q7 = new C0574q(3, 8, (kotlin.coroutines.h) obj3);
                c0574q7.m = (io.ktor.util.pipeline.e) obj;
                c0574q7.l = obj2;
                return c0574q7.invokeSuspend(Unit.a);
            case 9:
                C0574q c0574q8 = new C0574q(3, 9, (kotlin.coroutines.h) obj3);
                c0574q8.m = (io.ktor.util.pipeline.e) obj;
                c0574q8.l = (io.ktor.client.statement.c) obj2;
                return c0574q8.invokeSuspend(Unit.a);
            case 10:
                C0574q c0574q9 = new C0574q(3, 10, (kotlin.coroutines.h) obj3);
                c0574q9.m = (io.ktor.util.pipeline.e) obj;
                c0574q9.l = (io.ktor.client.statement.b) obj2;
                return c0574q9.invokeSuspend(Unit.a);
            default:
                C0574q c0574q10 = new C0574q((Function2) this.l, (kotlin.coroutines.h) obj3, 11);
                c0574q10.m = (io.ktor.util.pipeline.e) obj;
                return c0574q10.invokeSuspend(Unit.a);
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        androidx.work.impl.constraints.c cVar;
        InterfaceC5002j interfaceC5002j;
        io.ktor.util.pipeline.e eVar;
        Throwable cause;
        io.ktor.http.content.c c4861h;
        int i = 0;
        androidx.work.impl.constraints.c cVar2 = null;
        int i2 = 1;
        switch (this.j) {
            case 0:
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                int i3 = this.k;
                if (i3 == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    C0337m c0337m = ((r) this.m).b;
                    this.k = 1;
                    if (((androidx.compose.foundation.gestures.V) this.l).invoke(c0337m, this) == aVar) {
                        return aVar;
                    }
                } else {
                    if (i3 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                return Unit.a;
            case 1:
                kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
                int i4 = this.k;
                if (i4 == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    C0337m c0337m2 = ((r) this.m).b;
                    this.k = 1;
                    if (((androidx.compose.foundation.gestures.V) this.l).invoke(c0337m2, this) == aVar2) {
                        return aVar2;
                    }
                } else {
                    if (i4 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                return Unit.a;
            case 2:
                kotlin.coroutines.intrinsics.a aVar3 = kotlin.coroutines.intrinsics.a.a;
                int i5 = this.k;
                if (i5 == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    C1182m c1182m = (C1182m) this.m;
                    this.k = 1;
                    c1182m.getClass();
                    Object objE = c1182m.e(new C1166e((Bundle) this.l), this);
                    if (objE != aVar3) {
                        objE = Unit.a;
                    }
                    if (objE == aVar3) {
                        return aVar3;
                    }
                } else {
                    if (i5 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                return Unit.a;
            case 3:
                kotlin.coroutines.intrinsics.a aVar4 = kotlin.coroutines.intrinsics.a.a;
                int i6 = this.k;
                if (i6 == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    C1182m c1182m2 = (C1182m) this.m;
                    this.k = 1;
                    String str = (String) this.l;
                    c1182m2.getClass();
                    Object objE2 = c1182m2.e(new C1164d(str), this);
                    if (objE2 != aVar4) {
                        objE2 = Unit.a;
                    }
                    if (objE2 == aVar4) {
                        return aVar4;
                    }
                } else {
                    if (i6 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                return Unit.a;
            case 4:
                kotlin.coroutines.intrinsics.a aVar5 = kotlin.coroutines.intrinsics.a.a;
                int i7 = this.k;
                if (i7 != 0) {
                    if (i7 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.paging.I i8 = (androidx.paging.I) this.m;
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    return i8;
                }
                androidx.glance.appwidget.protobuf.Z.e(obj);
                androidx.paging.I i9 = (androidx.paging.I) this.m;
                androidx.paging.I i10 = (androidx.paging.I) this.l;
                this.m = i10;
                this.k = 1;
                ((y0) i9.b.e).j(null);
                return Unit.a == aVar5 ? aVar5 : i10;
            case 5:
                kotlin.coroutines.intrinsics.a aVar6 = kotlin.coroutines.intrinsics.a.a;
                int i11 = this.k;
                if (i11 == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    InterfaceC5002j interfaceC5002j2 = (InterfaceC5002j) this.m;
                    androidx.work.impl.constraints.c[] cVarArr = (androidx.work.impl.constraints.c[]) ((Object[]) this.l);
                    int length = cVarArr.length;
                    while (true) {
                        cVar = androidx.work.impl.constraints.a.a;
                        if (i < length) {
                            androidx.work.impl.constraints.c cVar3 = cVarArr[i];
                            if (Intrinsics.b(cVar3, cVar)) {
                                i++;
                            } else {
                                cVar2 = cVar3;
                            }
                        }
                    }
                    if (cVar2 != null) {
                        cVar = cVar2;
                    }
                    this.k = 1;
                    if (interfaceC5002j2.emit(cVar, this) == aVar6) {
                        return aVar6;
                    }
                } else {
                    if (i11 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                return Unit.a;
            case 6:
                kotlin.coroutines.intrinsics.a aVar7 = kotlin.coroutines.intrinsics.a.a;
                int i12 = this.k;
                if (i12 == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    interfaceC5002j = (InterfaceC5002j) this.m;
                    InterfaceC1076h interfaceC1076h = ((com.quizlet.local.datastore.preferences.J) this.l).a;
                    com.quizlet.local.datastore.preferences.F f = new com.quizlet.local.datastore.preferences.F(2, null);
                    this.m = interfaceC5002j;
                    this.k = 1;
                    obj = interfaceC1076h.a(f, this);
                    if (obj == aVar7) {
                        return aVar7;
                    }
                } else {
                    if (i12 != 1) {
                        if (i12 != 2) {
                            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                        }
                        androidx.glance.appwidget.protobuf.Z.e(obj);
                        return Unit.a;
                    }
                    interfaceC5002j = (InterfaceC5002j) this.m;
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                this.m = null;
                this.k = 2;
                if (interfaceC5002j.emit(obj, this) == aVar7) {
                    return aVar7;
                }
                return Unit.a;
            case 7:
                kotlin.coroutines.intrinsics.a aVar8 = kotlin.coroutines.intrinsics.a.a;
                int i13 = this.k;
                if (i13 == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    io.ktor.util.pipeline.e eVar2 = (io.ktor.util.pipeline.e) this.m;
                    try {
                        this.m = eVar2;
                        this.k = 1;
                        Object objC = eVar2.c(this);
                        if (objC == aVar8) {
                            return aVar8;
                        }
                        eVar = eVar2;
                        obj = objC;
                    } catch (Throwable th) {
                        eVar = eVar2;
                        cause = th;
                        com.quizlet.quizletandroid.ui.setcreation.managers.n nVar = ((io.ktor.client.c) this.l).j;
                        com.quizlet.quizletandroid.ui.login.di.a definition = io.ktor.client.utils.a.d;
                        io.ktor.client.statement.b response = ((io.ktor.client.call.b) eVar.a).d();
                        Intrinsics.checkNotNullParameter(response, "response");
                        Intrinsics.checkNotNullParameter(cause, "cause");
                        nVar.getClass();
                        Intrinsics.checkNotNullParameter(definition, "definition");
                        android.support.v4.media.session.a.A(((io.ktor.util.collections.a) nVar.b).a(definition));
                        throw cause;
                    }
                } else {
                    if (i13 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    eVar = (io.ktor.util.pipeline.e) this.m;
                    try {
                        androidx.glance.appwidget.protobuf.Z.e(obj);
                    } catch (Throwable th2) {
                        cause = th2;
                        com.quizlet.quizletandroid.ui.setcreation.managers.n nVar2 = ((io.ktor.client.c) this.l).j;
                        com.quizlet.quizletandroid.ui.login.di.a definition2 = io.ktor.client.utils.a.d;
                        io.ktor.client.statement.b response2 = ((io.ktor.client.call.b) eVar.a).d();
                        Intrinsics.checkNotNullParameter(response2, "response");
                        Intrinsics.checkNotNullParameter(cause, "cause");
                        nVar2.getClass();
                        Intrinsics.checkNotNullParameter(definition2, "definition");
                        android.support.v4.media.session.a.A(((io.ktor.util.collections.a) nVar2.b).a(definition2));
                        throw cause;
                    }
                }
                return Unit.a;
            case 8:
                kotlin.coroutines.intrinsics.a aVar9 = kotlin.coroutines.intrinsics.a.a;
                int i14 = this.k;
                if (i14 == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    io.ktor.util.pipeline.e eVar3 = (io.ktor.util.pipeline.e) this.m;
                    Object body = this.l;
                    io.ktor.http.l lVar = ((io.ktor.client.request.c) eVar3.a).c;
                    List list = io.ktor.http.n.a;
                    String strQ = lVar.q("Accept");
                    Object obj2 = eVar3.a;
                    if (strQ == null) {
                        ((io.ktor.client.request.c) obj2).c.m("Accept", "*/*");
                    }
                    io.ktor.http.d dVarC = Z6.c((io.ktor.client.request.c) obj2);
                    if (body instanceof String) {
                        String str2 = (String) body;
                        if (dVarC == null) {
                            dVarC = io.ktor.http.c.a;
                        }
                        c4861h = new io.ktor.http.content.d(str2, dVarC);
                    } else if (body instanceof byte[]) {
                        c4861h = new C4860g(dVarC, body);
                    } else if (body instanceof io.ktor.utils.io.n) {
                        c4861h = new C4861h(eVar3, dVarC, body);
                    } else if (body instanceof io.ktor.http.content.c) {
                        c4861h = (io.ktor.http.content.c) body;
                    } else {
                        io.ktor.client.request.c context = (io.ktor.client.request.c) obj2;
                        Intrinsics.checkNotNullParameter(context, "context");
                        Intrinsics.checkNotNullParameter(body, "body");
                        c4861h = body instanceof InputStream ? new C4861h(context, dVarC, body) : null;
                    }
                    if ((c4861h != null ? c4861h.b() : null) != null) {
                        io.ktor.client.request.c cVar4 = (io.ktor.client.request.c) obj2;
                        io.ktor.http.l lVar2 = cVar4.c;
                        lVar2.getClass();
                        Intrinsics.checkNotNullParameter("Content-Type", "name");
                        ((Map) lVar2.b).remove("Content-Type");
                        AbstractC4863j.a.n("Transformed with default transformers request body for " + cVar4.a + " from " + kotlin.jvm.internal.K.a(body.getClass()));
                        this.m = null;
                        this.k = 1;
                        if (eVar3.d(c4861h, this) == aVar9) {
                            return aVar9;
                        }
                    }
                } else {
                    if (i14 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                return Unit.a;
            case 9:
                kotlin.coroutines.intrinsics.a aVar10 = kotlin.coroutines.intrinsics.a.a;
                int i15 = this.k;
                if (i15 == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    io.ktor.util.pipeline.e eVar4 = (io.ktor.util.pipeline.e) this.m;
                    io.ktor.client.statement.c cVar5 = (io.ktor.client.statement.c) this.l;
                    io.ktor.util.reflect.a aVar11 = cVar5.a;
                    Object obj3 = cVar5.b;
                    if (!(obj3 instanceof io.ktor.utils.io.n)) {
                        return Unit.a;
                    }
                    if (aVar11.a.equals(kotlin.jvm.internal.K.a(InputStream.class))) {
                        io.ktor.utils.io.n nVar3 = (io.ktor.utils.io.n) obj3;
                        Intrinsics.checkNotNullParameter(nVar3, "<this>");
                        io.ktor.client.statement.c cVar6 = new io.ktor.client.statement.c(aVar11, new C4864k(new C4864k(nVar3, i2), i));
                        this.m = null;
                        this.k = 1;
                        if (eVar4.d(cVar6, this) == aVar10) {
                            return aVar10;
                        }
                    }
                } else {
                    if (i15 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                return Unit.a;
            case 10:
                kotlin.coroutines.intrinsics.a aVar12 = kotlin.coroutines.intrinsics.a.a;
                int i16 = this.k;
                if (i16 == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    io.ktor.util.pipeline.e eVar5 = (io.ktor.util.pipeline.e) this.m;
                    io.ktor.client.statement.b bVar = (io.ktor.client.statement.b) this.l;
                    io.ktor.util.e eVarF = bVar.b().f();
                    io.ktor.util.a key = AbstractC4866m.a;
                    eVarF.getClass();
                    Intrinsics.checkNotNullParameter(key, "key");
                    if (eVarF.c().containsKey(key)) {
                        return Unit.a;
                    }
                    io.ktor.client.plugins.internal.d dVar = new io.ktor.client.plugins.internal.d(bVar.c());
                    io.ktor.client.call.b originCall = bVar.b();
                    com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a block = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a(dVar, 20);
                    Intrinsics.checkNotNullParameter(originCall, "<this>");
                    Intrinsics.checkNotNullParameter(block, "block");
                    io.ktor.client.c client = originCall.a;
                    io.ktor.http.k responseHeaders = originCall.d().a();
                    Intrinsics.checkNotNullParameter(client, "client");
                    Intrinsics.checkNotNullParameter(block, "block");
                    Intrinsics.checkNotNullParameter(originCall, "originCall");
                    Intrinsics.checkNotNullParameter(responseHeaders, "responseHeaders");
                    io.ktor.client.plugins.observer.a aVar13 = new io.ktor.client.plugins.observer.a(client);
                    io.ktor.client.call.e eVar6 = new io.ktor.client.call.e(aVar13, originCall.c());
                    Intrinsics.checkNotNullParameter(eVar6, "<set-?>");
                    aVar13.b = eVar6;
                    io.ktor.client.plugins.observer.b bVar2 = new io.ktor.client.plugins.observer.b(aVar13, block, originCall.d(), responseHeaders);
                    Intrinsics.checkNotNullParameter(bVar2, "<set-?>");
                    aVar13.c = bVar2;
                    aVar13.f().e(AbstractC4866m.b, Unit.a);
                    io.ktor.client.statement.b bVarD = aVar13.d();
                    this.m = null;
                    this.k = 1;
                    if (eVar5.d(bVarD, this) == aVar12) {
                        return aVar12;
                    }
                } else {
                    if (i16 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                return Unit.a;
            default:
                kotlin.coroutines.intrinsics.a aVar14 = kotlin.coroutines.intrinsics.a.a;
                int i17 = this.k;
                if (i17 == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    Object obj4 = ((io.ktor.util.pipeline.e) this.m).a;
                    this.k = 1;
                    if (((Function2) this.l).invoke(obj4, this) == aVar14) {
                        return aVar14;
                    }
                } else {
                    if (i17 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                return Unit.a;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0574q(androidx.compose.foundation.gestures.Z z, androidx.compose.foundation.gestures.V v, kotlin.coroutines.h hVar, int i) {
        super(3, hVar);
        this.j = i;
        this.m = z;
        this.l = v;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0574q(Object obj, kotlin.coroutines.h hVar, int i) {
        super(3, hVar);
        this.j = i;
        this.l = obj;
    }
}
