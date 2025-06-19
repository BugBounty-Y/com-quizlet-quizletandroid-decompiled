package com.quizlet.remote.model.user.emailconfirmation;

import androidx.glance.appwidget.protobuf.Z;
import com.amazon.device.ads.DtbDeviceDataRetriever;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import com.quizlet.data.model.EnumC4171u1;
import com.quizlet.remote.model.base.ApiError;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.user.FullUserDataResponse;
import com.quizlet.remote.model.user.FullUserModels;
import com.quizlet.remote.model.user.RemoteFullUser;
import com.quizlet.remote.service.E;
import io.ktor.client.engine.okhttp.StreamAdapterIOException;
import io.ktor.client.network.sockets.ConnectTimeoutException;
import io.ktor.client.plugins.Y;
import io.ktor.client.plugins.b0;
import io.ktor.client.request.d;
import io.reactivex.rxjava3.core.q;
import io.reactivex.rxjava3.functions.h;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.Objects;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p;
import kotlin.r;
import kotlin.text.StringsKt;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C5028l;
import okhttp3.H;
import okhttp3.InterfaceC5076e;
import okhttp3.InterfaceC5077f;
import okhttp3.internal.connection.g;
import org.jsoup.SerializationException;
import org.jsoup.nodes.f;
import org.jsoup.select.n;

/* loaded from: classes3.dex */
public final class c implements InterfaceC5077f, q, n {
    public final Object a;
    public final Object b;

    public c(E service, AbstractC5040y ioDispatcher) {
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.a = service;
        this.b = ioDispatcher;
    }

    public static final EnumC4171u1 b(c cVar, ApiThreeWrapper apiThreeWrapper) {
        FullUserModels fullUserModels;
        List list;
        RemoteFullUser remoteFullUser;
        cVar.getClass();
        ApiError apiError = apiThreeWrapper.b;
        if (Intrinsics.b(apiError != null ? apiError.b : null, "exception_too_many_confirmation_resends")) {
            return EnumC4171u1.c;
        }
        FullUserDataResponse fullUserDataResponse = (FullUserDataResponse) apiThreeWrapper.a();
        return (fullUserDataResponse == null || (fullUserModels = fullUserDataResponse.d) == null || (list = fullUserModels.a) == null || (remoteFullUser = (RemoteFullUser) CollectionsKt.firstOrNull(list)) == null) ? false : Intrinsics.b(remoteFullUser.u, Boolean.FALSE) ? EnumC4171u1.a : EnumC4171u1.b;
    }

    @Override // io.reactivex.rxjava3.core.q
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        ((q) this.a).a(bVar);
    }

    @Override // org.jsoup.select.n
    public void d(org.jsoup.nodes.n nVar, int i) {
        try {
            nVar.t((StringBuilder) this.a, i, (f) this.b);
        } catch (IOException e) {
            throw new SerializationException(e);
        }
    }

    @Override // org.jsoup.select.n
    public void i(org.jsoup.nodes.n nVar, int i) {
        if (nVar.r().equals("#text")) {
            return;
        }
        try {
            nVar.u((StringBuilder) this.a, i, (f) this.b);
        } catch (IOException e) {
            throw new SerializationException(e);
        }
    }

    @Override // io.reactivex.rxjava3.core.q
    public void onError(Throwable th) {
        ((q) this.a).onError(th);
    }

    @Override // okhttp3.InterfaceC5077f
    public void onFailure(InterfaceC5076e call, IOException e) {
        Throwable connectTimeoutException;
        Object obj;
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(e, "e");
        C5028l c5028l = (C5028l) this.b;
        if (c5028l.x()) {
            return;
        }
        p pVar = r.b;
        if (e instanceof StreamAdapterIOException) {
            connectTimeoutException = e.getCause();
            if (connectTimeoutException != null) {
                e = connectTimeoutException;
            }
        } else if (e instanceof SocketTimeoutException) {
            String message = e.getMessage();
            d request = (d) this.a;
            if (message == null || !StringsKt.G(message, "connect", true)) {
                e = b0.a(request, e);
            } else {
                org.slf4j.b bVar = b0.a;
                Intrinsics.checkNotNullParameter(request, "request");
                StringBuilder sb = new StringBuilder("Connect timeout has expired [url=");
                sb.append(request.a);
                sb.append(", connect_timeout=");
                Y y = (Y) request.a();
                if (y == null || (obj = y.b) == null) {
                    obj = DtbDeviceDataRetriever.ORIENTATION_UNKNOWN;
                }
                connectTimeoutException = new ConnectTimeoutException(android.support.v4.media.session.a.s(sb, obj, " ms]"), e);
                e = connectTimeoutException;
            }
        }
        c5028l.resumeWith(Z.b(e));
    }

    @Override // okhttp3.InterfaceC5077f
    public void onResponse(InterfaceC5076e call, H response) {
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(response, "response");
        if (((g) call).o) {
            return;
        }
        C5028l c5028l = (C5028l) this.b;
        p pVar = r.b;
        c5028l.resumeWith(response);
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        try {
            Object objApply = ((h) this.b).apply(obj);
            Objects.requireNonNull(objApply, "The mapper function returned a null value.");
            ((q) this.a).onSuccess(objApply);
        } catch (Throwable th) {
            x7.b(th);
            onError(th);
        }
    }

    public c(d requestData, C5028l continuation) {
        Intrinsics.checkNotNullParameter(requestData, "requestData");
        Intrinsics.checkNotNullParameter(continuation, "continuation");
        this.a = requestData;
        this.b = continuation;
    }

    public c(q qVar, h hVar) {
        this.a = qVar;
        this.b = hVar;
    }

    public c(StringBuilder sb, f fVar) {
        this.a = sb;
        this.b = fVar;
        fVar.c();
    }
}
