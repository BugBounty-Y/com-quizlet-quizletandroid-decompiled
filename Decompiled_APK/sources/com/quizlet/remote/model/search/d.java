package com.quizlet.remote.model.search;

import androidx.transition.C1412o;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.quizlet.remote.service.G;
import com.quizlet.remote.service.y;
import io.reactivex.rxjava3.core.q;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.maybe.i;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.C5057k;
import kotlinx.serialization.internal.m0;
import okhttp3.w;
import retrofit2.InterfaceC5186k;
import retrofit2.L;

/* loaded from: classes3.dex */
public final class d implements h, q, m0, InterfaceC5186k {
    public final Object a;
    public final Object b;

    public /* synthetic */ d(Object obj, Object obj2) {
        this.a = obj;
        this.b = obj2;
    }

    @Override // io.reactivex.rxjava3.core.q
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.internal.disposables.a.c((i) this.a, bVar);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        Throwable it2 = (Throwable) obj;
        Intrinsics.checkNotNullParameter(it2, "it");
        Throwable thB = G.b((G) this.a, (L) ((com.quizlet.data.repository.folderset.c) this.b).b, it2);
        Objects.requireNonNull(thB, "throwable is null");
        return new io.reactivex.rxjava3.internal.operators.completable.c(thB, 3);
    }

    @Override // kotlinx.serialization.internal.m0
    public KSerializer b(kotlin.reflect.c key) {
        Object objPutIfAbsent;
        Intrinsics.checkNotNullParameter(key, "key");
        ConcurrentHashMap concurrentHashMap = (ConcurrentHashMap) this.b;
        Class clsB = kotlin.jvm.a.b(key);
        Object c5057k = concurrentHashMap.get(clsB);
        if (c5057k == null && (objPutIfAbsent = concurrentHashMap.putIfAbsent(clsB, (c5057k = new C5057k((KSerializer) ((Function1) this.a).invoke(key))))) != null) {
            c5057k = objPutIfAbsent;
        }
        return ((C5057k) c5057k).a;
    }

    @Override // retrofit2.InterfaceC5186k
    public Object convert(Object obj) throws JsonProcessingException {
        byte[] content = ((ObjectWriter) this.a).writeValueAsBytes(obj);
        Intrinsics.checkNotNullParameter(content, "content");
        int length = content.length;
        Intrinsics.checkNotNullParameter(content, "content");
        return C1412o.e(length, (w) this.b, content);
    }

    @Override // io.reactivex.rxjava3.core.q
    public void onError(Throwable th) {
        ((io.reactivex.rxjava3.core.h) this.b).onError(th);
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        ((io.reactivex.rxjava3.core.h) this.b).onSuccess(obj);
    }

    public d(y service, com.quizlet.quizletandroid.ui.common.images.capture.b misspellingsMapper, AbstractC5040y ioDispatcher) {
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(misspellingsMapper, "misspellingsMapper");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.a = service;
        this.b = ioDispatcher;
    }

    public d(Function1 compute) {
        Intrinsics.checkNotNullParameter(compute, "compute");
        this.a = compute;
        this.b = new ConcurrentHashMap();
    }
}
