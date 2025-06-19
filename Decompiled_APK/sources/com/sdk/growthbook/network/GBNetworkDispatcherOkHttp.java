package com.sdk.growthbook.network;

import androidx.glance.appwidget.protobuf.Z;
import androidx.transition.C1412o;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3336f;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import com.google.android.gms.internal.mlkit_vision_camera.F1;
import com.google.firebase.perf.network.FirebasePerfOkHttpClient;
import com.quizlet.infra.legacysyncengine.tasks.parse.b;
import com.sdk.growthbook.DispatcherKt;
import com.sdk.growthbook.utils.GBEventSourceHandler;
import com.sdk.growthbook.utils.GBEventSourceListener;
import com.sdk.growthbook.utils.Resource;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.intrinsics.a;
import kotlin.coroutines.jvm.internal.e;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.InterfaceC5025j0;
import kotlinx.coroutines.channels.t;
import kotlinx.coroutines.channels.u;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.e0;
import okhttp3.A;
import okhttp3.E;
import okhttp3.H;
import okhttp3.InterfaceC5076e;
import okhttp3.InterfaceC5077f;
import okhttp3.J;
import okhttp3.internal.connection.g;
import okhttp3.o;
import okhttp3.w;
import okhttp3.z;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class GBNetworkDispatcherOkHttp implements NetworkDispatcher {

    @NotNull
    private final A client;
    private boolean enableLogging;

    @Metadata
    @e(c = "com.sdk.growthbook.network.GBNetworkDispatcherOkHttp$consumeGETRequest$1", f = "GBNetworkDispatcherOkHttp.kt", l = {}, m = "invokeSuspend")
    /* renamed from: com.sdk.growthbook.network.GBNetworkDispatcherOkHttp$consumeGETRequest$1, reason: invalid class name */
    public static final class AnonymousClass1 extends i implements Function2<C, h<? super Unit>, Object> {
        final /* synthetic */ Function1<Throwable, Unit> $onError;
        final /* synthetic */ Function1<String, Unit> $onSuccess;
        final /* synthetic */ String $request;
        int label;
        final /* synthetic */ GBNetworkDispatcherOkHttp this$0;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        /* JADX WARN: Multi-variable type inference failed */
        public AnonymousClass1(String str, GBNetworkDispatcherOkHttp gBNetworkDispatcherOkHttp, Function1<? super Throwable, Unit> function1, Function1<? super String, Unit> function12, h<? super AnonymousClass1> hVar) {
            super(2, hVar);
            this.$request = str;
            this.this$0 = gBNetworkDispatcherOkHttp;
            this.$onError = function1;
            this.$onSuccess = function12;
        }

        @Override // kotlin.coroutines.jvm.internal.a
        @NotNull
        public final h<Unit> create(Object obj, @NotNull h<?> hVar) {
            return new AnonymousClass1(this.$request, this.this$0, this.$onError, this.$onSuccess, hVar);
        }

        @Override // kotlin.coroutines.jvm.internal.a
        public final Object invokeSuspend(@NotNull Object obj) {
            a aVar = a.a;
            if (this.label != 0) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            com.quizlet.remote.model.notes.e eVar = new com.quizlet.remote.model.notes.e(13);
            eVar.r(this.$request);
            g gVarC = this.this$0.client.c(eVar.i());
            final Function1<Throwable, Unit> function1 = this.$onError;
            final Function1<String, Unit> function12 = this.$onSuccess;
            FirebasePerfOkHttpClient.enqueue(gVarC, new InterfaceC5077f() { // from class: com.sdk.growthbook.network.GBNetworkDispatcherOkHttp.consumeGETRequest.1.1
                @Override // okhttp3.InterfaceC5077f
                public void onFailure(@NotNull InterfaceC5076e call, @NotNull IOException e) {
                    Intrinsics.checkNotNullParameter(call, "call");
                    Intrinsics.checkNotNullParameter(e, "e");
                    function1.invoke(e);
                }

                @Override // okhttp3.InterfaceC5077f
                public void onResponse(@NotNull InterfaceC5076e call, @NotNull H response) {
                    Unit unit;
                    Intrinsics.checkNotNullParameter(call, "call");
                    Intrinsics.checkNotNullParameter(response, "response");
                    Function1<Throwable, Unit> function13 = function1;
                    Function1<String, Unit> function14 = function12;
                    try {
                        if (response.d()) {
                            int i = response.d;
                            if (200 <= i && i < 300) {
                                J j = response.g;
                                if (j != null) {
                                    function14.invoke(j.f());
                                    unit = Unit.a;
                                } else {
                                    unit = null;
                                }
                                if (unit == null) {
                                    function13.invoke(new Exception("Response body is null: " + j));
                                }
                                Unit unit2 = Unit.a;
                                response.close();
                                return;
                            }
                        }
                        function13.invoke(new IOException("Unexpected code " + response));
                        response.close();
                    } catch (Throwable th) {
                        try {
                            throw th;
                        } catch (Throwable th2) {
                            AbstractC3336f.c(response, th);
                            throw th2;
                        }
                    }
                }
            });
            return Unit.a;
        }

        @Override // kotlin.jvm.functions.Function2
        public final Object invoke(@NotNull C c, h<? super Unit> hVar) {
            return ((AnonymousClass1) create(c, hVar)).invokeSuspend(Unit.a);
        }
    }

    @Metadata
    @e(c = "com.sdk.growthbook.network.GBNetworkDispatcherOkHttp$consumePOSTRequest$1", f = "GBNetworkDispatcherOkHttp.kt", l = {}, m = "invokeSuspend")
    /* renamed from: com.sdk.growthbook.network.GBNetworkDispatcherOkHttp$consumePOSTRequest$1, reason: invalid class name and case insensitive filesystem */
    public static final class C48431 extends i implements Function2<C, h<? super Unit>, Object> {
        final /* synthetic */ Map<String, Object> $bodyParams;
        final /* synthetic */ Function1<Throwable, Unit> $onError;
        final /* synthetic */ Function1<String, Unit> $onSuccess;
        final /* synthetic */ String $url;
        int label;
        final /* synthetic */ GBNetworkDispatcherOkHttp this$0;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        /* JADX WARN: Multi-variable type inference failed */
        public C48431(Map<String, ? extends Object> map, String str, GBNetworkDispatcherOkHttp gBNetworkDispatcherOkHttp, Function1<? super Throwable, Unit> function1, Function1<? super String, Unit> function12, h<? super C48431> hVar) {
            super(2, hVar);
            this.$bodyParams = map;
            this.$url = str;
            this.this$0 = gBNetworkDispatcherOkHttp;
            this.$onError = function1;
            this.$onSuccess = function12;
        }

        @Override // kotlin.coroutines.jvm.internal.a
        @NotNull
        public final h<Unit> create(Object obj, @NotNull h<?> hVar) {
            return new C48431(this.$bodyParams, this.$url, this.this$0, this.$onError, this.$onSuccess, hVar);
        }

        @Override // kotlin.coroutines.jvm.internal.a
        public final Object invokeSuspend(@NotNull Object obj) {
            a aVar = a.a;
            if (this.label != 0) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            Pattern pattern = w.e;
            E body = C1412o.f(GBNetworkDispatcherOkHttpKt.toJsonElement(this.$bodyParams).toString(), AbstractC3347h2.d("application/json; charset=utf-8"));
            com.quizlet.remote.model.notes.e eVar = new com.quizlet.remote.model.notes.e(13);
            eVar.r(this.$url);
            eVar.h("Content-Type", "application/json");
            eVar.h("Accept", "application/json");
            Intrinsics.checkNotNullParameter(body, "body");
            eVar.n("POST", body);
            g gVarC = this.this$0.client.c(eVar.i());
            final Function1<Throwable, Unit> function1 = this.$onError;
            final Function1<String, Unit> function12 = this.$onSuccess;
            FirebasePerfOkHttpClient.enqueue(gVarC, new InterfaceC5077f() { // from class: com.sdk.growthbook.network.GBNetworkDispatcherOkHttp.consumePOSTRequest.1.1
                @Override // okhttp3.InterfaceC5077f
                public void onFailure(@NotNull InterfaceC5076e call, @NotNull IOException e) {
                    Intrinsics.checkNotNullParameter(call, "call");
                    Intrinsics.checkNotNullParameter(e, "e");
                    function1.invoke(e);
                }

                @Override // okhttp3.InterfaceC5077f
                public void onResponse(@NotNull InterfaceC5076e call, @NotNull H response) {
                    Unit unit;
                    Intrinsics.checkNotNullParameter(call, "call");
                    Intrinsics.checkNotNullParameter(response, "response");
                    Function1<Throwable, Unit> function13 = function1;
                    Function1<String, Unit> function14 = function12;
                    try {
                        if (response.d()) {
                            int i = response.d;
                            if (200 <= i && i < 300) {
                                J j = response.g;
                                if (j != null) {
                                    function14.invoke(j.f());
                                    unit = Unit.a;
                                } else {
                                    unit = null;
                                }
                                if (unit == null) {
                                    function13.invoke(new IOException("Response body is null: " + j));
                                }
                                Unit unit2 = Unit.a;
                                response.close();
                                return;
                            }
                        }
                        function13.invoke(new IOException("Unexpected code " + response));
                        response.close();
                    } catch (Throwable th) {
                        try {
                            throw th;
                        } catch (Throwable th2) {
                            AbstractC3336f.c(response, th);
                            throw th2;
                        }
                    }
                }
            });
            return Unit.a;
        }

        @Override // kotlin.jvm.functions.Function2
        public final Object invoke(@NotNull C c, h<? super Unit> hVar) {
            return ((C48431) create(c, hVar)).invokeSuspend(Unit.a);
        }
    }

    @Metadata
    @e(c = "com.sdk.growthbook.network.GBNetworkDispatcherOkHttp$consumeSSEConnection$1", f = "GBNetworkDispatcherOkHttp.kt", l = {151}, m = "invokeSuspend")
    /* renamed from: com.sdk.growthbook.network.GBNetworkDispatcherOkHttp$consumeSSEConnection$1, reason: invalid class name and case insensitive filesystem */
    public static final class C48441 extends i implements Function2<u, h<? super Unit>, Object> {
        final /* synthetic */ okhttp3.C $request;
        final /* synthetic */ A $sseHttpClient;
        private /* synthetic */ Object L$0;
        int label;
        final /* synthetic */ GBNetworkDispatcherOkHttp this$0;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C48441(A a, okhttp3.C c, GBNetworkDispatcherOkHttp gBNetworkDispatcherOkHttp, h<? super C48441> hVar) {
            super(2, hVar);
            this.$sseHttpClient = a;
            this.$request = c;
            this.this$0 = gBNetworkDispatcherOkHttp;
        }

        @Override // kotlin.coroutines.jvm.internal.a
        @NotNull
        public final h<Unit> create(Object obj, @NotNull h<?> hVar) {
            C48441 c48441 = new C48441(this.$sseHttpClient, this.$request, this.this$0, hVar);
            c48441.L$0 = obj;
            return c48441;
        }

        @Override // kotlin.coroutines.jvm.internal.a
        public final Object invokeSuspend(@NotNull Object obj) {
            a aVar = a.a;
            int i = this.label;
            if (i == 0) {
                Z.e(obj);
                final u uVar = (u) this.L$0;
                A client = this.$sseHttpClient;
                Intrinsics.checkNotNullParameter(client, "client");
                b bVar = new b(client, 27);
                okhttp3.C request = this.$request;
                GBEventSourceListener listener = new GBEventSourceListener(new GBEventSourceHandler() { // from class: com.sdk.growthbook.network.GBNetworkDispatcherOkHttp.consumeSSEConnection.1.1
                    @Override // com.sdk.growthbook.utils.GBEventSourceHandler
                    public void onClose(okhttp3.sse.a aVar2) {
                        if (aVar2 != null) {
                            g gVar = (g) ((io.reactivex.rxjava3.internal.operators.single.i) aVar2).b;
                            if (gVar == null) {
                                Intrinsics.m("call");
                                throw null;
                            }
                            gVar.cancel();
                        }
                        kotlinx.coroutines.E.i(uVar, null);
                    }

                    @Override // com.sdk.growthbook.utils.GBEventSourceHandler
                    public void onFeaturesResponse(String str) {
                        if (str != null) {
                            u uVar2 = uVar;
                            ((t) uVar2).d.o(new Resource.Success(str));
                        }
                    }
                }, this.this$0.enableLogging);
                A client2 = (A) bVar.b;
                Intrinsics.checkNotNullParameter(client2, "$client");
                Intrinsics.checkNotNullParameter(request, "request");
                Intrinsics.checkNotNullParameter(listener, "listener");
                if (request.a("Accept") == null) {
                    com.quizlet.remote.model.notes.e eVarB = request.b();
                    eVarB.h("Accept", "text/event-stream");
                    request = eVarB.i();
                }
                io.reactivex.rxjava3.internal.operators.single.i iVar = new io.reactivex.rxjava3.internal.operators.single.i(request, listener);
                Intrinsics.checkNotNullParameter(client2, "client");
                z zVarB = client2.b();
                o eventListener = o.c;
                Intrinsics.checkNotNullParameter(eventListener, "eventListener");
                byte[] bArr = okhttp3.internal.b.a;
                Intrinsics.checkNotNullParameter(eventListener, "<this>");
                zVarB.e = new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(22);
                g gVarC = new A(zVarB).c(request);
                iVar.b = gVarC;
                gVarC.e(iVar);
                this.label = 1;
                if (F1.a(uVar, new io.ktor.client.plugins.api.b(6), this) == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            return Unit.a;
        }

        @Override // kotlin.jvm.functions.Function2
        public final Object invoke(@NotNull u uVar, h<? super Unit> hVar) {
            return ((C48441) create(uVar, hVar)).invokeSuspend(Unit.a);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public GBNetworkDispatcherOkHttp() {
        this(null, false, 3, 0 == true ? 1 : 0);
    }

    @Override // com.sdk.growthbook.network.NetworkDispatcher
    @NotNull
    public InterfaceC5025j0 consumeGETRequest(@NotNull String request, @NotNull Function1<? super String, Unit> onSuccess, @NotNull Function1<? super Throwable, Unit> onError) {
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(onSuccess, "onSuccess");
        Intrinsics.checkNotNullParameter(onError, "onError");
        return kotlinx.coroutines.E.A(kotlinx.coroutines.E.c(DispatcherKt.getPlatformDependentIODispatcher()), null, null, new AnonymousClass1(request, this, onError, onSuccess, null), 3);
    }

    @Override // com.sdk.growthbook.network.NetworkDispatcher
    public void consumePOSTRequest(@NotNull String url, @NotNull Map<String, ? extends Object> bodyParams, @NotNull Function1<? super String, Unit> onSuccess, @NotNull Function1<? super Throwable, Unit> onError) {
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(bodyParams, "bodyParams");
        Intrinsics.checkNotNullParameter(onSuccess, "onSuccess");
        Intrinsics.checkNotNullParameter(onError, "onError");
        kotlinx.coroutines.E.A(kotlinx.coroutines.E.c(DispatcherKt.getPlatformDependentIODispatcher()), null, null, new C48431(bodyParams, url, this, onError, onSuccess, null), 3);
    }

    @Override // com.sdk.growthbook.network.NetworkDispatcher
    @NotNull
    public InterfaceC4992i consumeSSEConnection(@NotNull String url) {
        Intrinsics.checkNotNullParameter(url, "url");
        z zVar = new z();
        zVar.f = true;
        TimeUnit unit = TimeUnit.SECONDS;
        Intrinsics.checkNotNullParameter(unit, "unit");
        zVar.v = okhttp3.internal.b.b("timeout", 0L, unit);
        zVar.c(0L, unit);
        Intrinsics.checkNotNullParameter(unit, "unit");
        zVar.x = okhttp3.internal.b.b("timeout", 0L, unit);
        A a = new A(zVar);
        com.quizlet.remote.model.notes.e eVar = new com.quizlet.remote.model.notes.e(13);
        eVar.r(url);
        eVar.l("Accept", "application/json; q=0.5");
        eVar.h("Accept", "text/event-stream");
        return e0.g(new C48441(a, eVar.i(), this, null));
    }

    public final void setLoggingEnabled(boolean z) {
        this.enableLogging = z;
    }

    public GBNetworkDispatcherOkHttp(@NotNull A client, boolean z) {
        Intrinsics.checkNotNullParameter(client, "client");
        this.client = client;
        this.enableLogging = z;
    }

    public /* synthetic */ GBNetworkDispatcherOkHttp(A a, boolean z, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? new A() : a, (i & 2) != 0 ? false : z);
    }
}
