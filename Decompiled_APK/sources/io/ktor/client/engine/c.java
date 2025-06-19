package io.ktor.client.engine;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.U6;
import com.google.android.gms.internal.mlkit_vision_barcode.Z6;
import io.ktor.client.plugins.V;
import io.ktor.client.plugins.W;
import io.ktor.client.plugins.e0;
import io.ktor.http.A;
import io.ktor.http.UnsafeHeaderException;
import io.ktor.http.m;
import io.ktor.http.n;
import io.ktor.http.p;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.U;
import kotlin.text.x;
import kotlinx.coroutines.A0;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public final /* synthetic */ int j;
    public int k;
    public /* synthetic */ Object l;
    public /* synthetic */ Object m;
    public final /* synthetic */ io.ktor.client.c n;
    public final /* synthetic */ Object o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(io.ktor.client.c cVar, io.ktor.client.engine.okhttp.f fVar, kotlin.coroutines.h hVar) {
        super(3, hVar);
        this.j = 0;
        this.n = cVar;
        this.o = fVar;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        switch (this.j) {
            case 0:
                io.ktor.client.engine.okhttp.f fVar = (io.ktor.client.engine.okhttp.f) this.o;
                c cVar = new c(this.n, fVar, (kotlin.coroutines.h) obj3);
                cVar.l = (io.ktor.util.pipeline.e) obj;
                cVar.m = obj2;
                return cVar.invokeSuspend(Unit.a);
            case 1:
                c cVar2 = new c((W) this.o, this.n, (kotlin.coroutines.h) obj3, 1);
                cVar2.l = (io.ktor.util.pipeline.e) obj;
                cVar2.m = obj2;
                return cVar2.invokeSuspend(Unit.a);
            default:
                c cVar3 = new c((kotlin.jvm.functions.c) this.o, this.n, (kotlin.coroutines.h) obj3, 2);
                cVar3.l = (e0) obj;
                cVar3.m = (io.ktor.client.request.c) obj2;
                return cVar3.invokeSuspend(Unit.a);
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        U uC;
        io.ktor.client.engine.okhttp.f fVar;
        Object objA;
        io.ktor.util.pipeline.e eVar;
        io.ktor.client.request.d requestData;
        g gVar;
        U uC2;
        io.ktor.util.pipeline.e eVar2;
        U uC3;
        Object objA2;
        U uC4;
        switch (this.j) {
            case 0:
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                int i = this.k;
                io.ktor.client.c client = this.n;
                if (i == 0) {
                    Z.e(obj);
                    io.ktor.util.pipeline.e eVar3 = (io.ktor.util.pipeline.e) this.l;
                    Object obj2 = this.m;
                    io.ktor.client.request.c cVar = new io.ktor.client.request.c();
                    io.ktor.client.request.c builder = (io.ktor.client.request.c) eVar3.a;
                    Intrinsics.checkNotNullParameter(builder, "builder");
                    cVar.e = builder.e;
                    cVar.b(builder);
                    if (obj2 == null) {
                        io.ktor.http.content.a aVar2 = io.ktor.http.content.a.a;
                        Intrinsics.checkNotNullParameter(aVar2, "<set-?>");
                        cVar.d = aVar2;
                        C4950i c4950iA = K.a(Object.class);
                        try {
                            uC2 = K.c(Object.class);
                        } catch (Throwable unused) {
                            uC2 = null;
                        }
                        cVar.a(new io.ktor.util.reflect.a(c4950iA, uC2));
                    } else if (obj2 instanceof io.ktor.http.content.c) {
                        Intrinsics.checkNotNullParameter(obj2, "<set-?>");
                        cVar.d = obj2;
                        cVar.a(null);
                    } else {
                        Intrinsics.checkNotNullParameter(obj2, "<set-?>");
                        cVar.d = obj2;
                        C4950i c4950iA2 = K.a(Object.class);
                        try {
                            uC = K.c(Object.class);
                        } catch (Throwable unused2) {
                            uC = null;
                        }
                        cVar.a(new io.ktor.util.reflect.a(c4950iA2, uC));
                    }
                    client.j.i(io.ktor.client.utils.a.b);
                    A aB = cVar.a.b();
                    p pVar = cVar.b;
                    Map values = (Map) cVar.c.b;
                    Intrinsics.checkNotNullParameter(values, "values");
                    m mVar = new m(values);
                    Object obj3 = cVar.d;
                    io.ktor.http.content.c cVar2 = obj3 instanceof io.ktor.http.content.c ? (io.ktor.http.content.c) obj3 : null;
                    if (cVar2 == null) {
                        throw new IllegalStateException(("No request transformation found: " + cVar.d).toString());
                    }
                    A0 a0 = cVar.e;
                    io.ktor.util.e eVar4 = cVar.f;
                    io.ktor.client.request.d dVar = new io.ktor.client.request.d(aB, pVar, mVar, cVar2, a0, eVar4);
                    eVar4.e(i.b, client.k);
                    Set setKeySet = mVar.c.keySet();
                    Intrinsics.checkNotNullParameter(setKeySet, "<this>");
                    Set setUnmodifiableSet = Collections.unmodifiableSet(setKeySet);
                    Intrinsics.checkNotNullExpressionValue(setUnmodifiableSet, "unmodifiableSet(...)");
                    ArrayList arrayList = new ArrayList();
                    for (Object obj4 : setUnmodifiableSet) {
                        if (n.a.contains((String) obj4)) {
                            arrayList.add(obj4);
                        }
                    }
                    if (!arrayList.isEmpty()) {
                        String header = arrayList.toString();
                        Intrinsics.checkNotNullParameter(header, "header");
                        throw new UnsafeHeaderException("Header(s) " + header + " are controlled by the engine and cannot be set explicitly");
                    }
                    Iterator it2 = dVar.g.iterator();
                    do {
                        boolean zHasNext = it2.hasNext();
                        fVar = (io.ktor.client.engine.okhttp.f) this.o;
                        if (zHasNext) {
                            gVar = (g) it2.next();
                        } else {
                            this.l = eVar3;
                            this.m = dVar;
                            this.k = 1;
                            objA = U6.a(fVar, dVar, this);
                            if (objA == aVar) {
                                return aVar;
                            }
                            eVar = eVar3;
                            requestData = dVar;
                        }
                    } while (fVar.e.contains(gVar));
                    throw new IllegalArgumentException(("Engine doesn't support " + gVar).toString());
                }
                if (i != 1) {
                    if (i != 2) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    Z.e(obj);
                    return Unit.a;
                }
                requestData = (io.ktor.client.request.d) this.m;
                io.ktor.util.pipeline.e eVar5 = (io.ktor.util.pipeline.e) this.l;
                Z.e(obj);
                eVar = eVar5;
                objA = obj;
                io.ktor.client.request.g responseData = (io.ktor.client.request.g) objA;
                Intrinsics.checkNotNullParameter(client, "client");
                Intrinsics.checkNotNullParameter(requestData, "requestData");
                Intrinsics.checkNotNullParameter(responseData, "responseData");
                io.ktor.client.call.b bVar = new io.ktor.client.call.b(client);
                io.ktor.client.request.a aVar3 = new io.ktor.client.request.a(bVar, requestData);
                Intrinsics.checkNotNullParameter(aVar3, "<set-?>");
                bVar.b = aVar3;
                io.ktor.client.call.f fVar2 = new io.ktor.client.call.f(bVar, responseData);
                Intrinsics.checkNotNullParameter(fVar2, "<set-?>");
                bVar.c = fVar2;
                Object obj5 = responseData.e;
                if (!(obj5 instanceof io.ktor.utils.io.n)) {
                    bVar.f().e(io.ktor.client.call.b.e, obj5);
                }
                io.ktor.client.statement.b bVarD = bVar.d();
                client.j.i(io.ktor.client.utils.a.c);
                E.s(bVarD.getCoroutineContext()).Q(new io.ktor.client.a(client, bVarD));
                this.l = null;
                this.m = null;
                this.k = 2;
                if (eVar.d(bVar, this) == aVar) {
                    return aVar;
                }
                return Unit.a;
            case 1:
                kotlin.coroutines.intrinsics.a aVar4 = kotlin.coroutines.intrinsics.a.a;
                int i2 = this.k;
                if (i2 == 0) {
                    Z.e(obj);
                    eVar2 = (io.ktor.util.pipeline.e) this.l;
                    Object obj6 = this.m;
                    if (!(obj6 instanceof io.ktor.http.content.c)) {
                        throw new IllegalStateException(x.d("\n|Fail to prepare request body for sending. \n|The body type is: " + K.a(obj6.getClass()) + ", with Content-Type: " + Z6.c((io.ktor.client.request.c) eVar2.a) + ".\n|\n|If you expect serialized body, please check that you have installed the corresponding plugin(like `ContentNegotiation`) and set `Content-Type` header.").toString());
                    }
                    io.ktor.client.request.c cVar3 = (io.ktor.client.request.c) eVar2.a;
                    if (obj6 == null) {
                        io.ktor.http.content.a aVar5 = io.ktor.http.content.a.a;
                        cVar3.getClass();
                        Intrinsics.checkNotNullParameter(aVar5, "<set-?>");
                        cVar3.d = aVar5;
                        C4950i c4950iA3 = K.a(io.ktor.http.content.c.class);
                        try {
                            uC4 = K.c(io.ktor.http.content.c.class);
                        } catch (Throwable unused3) {
                            uC4 = null;
                        }
                        cVar3.a(new io.ktor.util.reflect.a(c4950iA3, uC4));
                    } else if (obj6 != null) {
                        cVar3.getClass();
                        Intrinsics.checkNotNullParameter(obj6, "<set-?>");
                        cVar3.d = obj6;
                        cVar3.a(null);
                    } else {
                        cVar3.getClass();
                        Intrinsics.checkNotNullParameter(obj6, "<set-?>");
                        cVar3.d = obj6;
                        C4950i c4950iA4 = K.a(io.ktor.http.content.c.class);
                        try {
                            uC3 = K.c(io.ktor.http.content.c.class);
                        } catch (Throwable unused4) {
                            uC3 = null;
                        }
                        cVar3.a(new io.ktor.util.reflect.a(c4950iA4, uC3));
                    }
                    W w = (W) this.o;
                    e0 u = new io.ktor.client.plugins.U(w.a, this.n);
                    Iterator it3 = CollectionsKt.g0(w.b).iterator();
                    while (it3.hasNext()) {
                        u = new V((kotlin.jvm.functions.c) it3.next(), u);
                    }
                    io.ktor.client.request.c cVar4 = (io.ktor.client.request.c) eVar2.a;
                    this.l = eVar2;
                    this.k = 1;
                    objA2 = u.a(cVar4, this);
                    if (objA2 == aVar4) {
                        return aVar4;
                    }
                } else {
                    if (i2 != 1) {
                        if (i2 != 2) {
                            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                        }
                        Z.e(obj);
                        return Unit.a;
                    }
                    eVar2 = (io.ktor.util.pipeline.e) this.l;
                    Z.e(obj);
                    objA2 = obj;
                }
                this.l = null;
                this.k = 2;
                if (eVar2.d((io.ktor.client.call.b) objA2, this) == aVar4) {
                    return aVar4;
                }
                return Unit.a;
            default:
                kotlin.coroutines.intrinsics.a aVar6 = kotlin.coroutines.intrinsics.a.a;
                int i3 = this.k;
                if (i3 != 0) {
                    if (i3 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    Z.e(obj);
                    return obj;
                }
                Z.e(obj);
                e0 e0Var = (e0) this.l;
                io.ktor.client.request.c cVar5 = (io.ktor.client.request.c) this.m;
                io.ktor.client.plugins.api.g gVar2 = new io.ktor.client.plugins.api.g(e0Var, this.n.d);
                this.l = null;
                this.k = 1;
                Object objInvoke = ((kotlin.jvm.functions.c) this.o).invoke(gVar2, cVar5, this);
                return objInvoke == aVar6 ? aVar6 : objInvoke;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c(Object obj, io.ktor.client.c cVar, kotlin.coroutines.h hVar, int i) {
        super(3, hVar);
        this.j = i;
        this.o = obj;
        this.n = cVar;
    }
}
