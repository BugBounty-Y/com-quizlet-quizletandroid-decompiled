package com.quizlet.remote.model.union.folderwithcreator;

import androidx.camera.camera2.internal.p0;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import com.quizlet.local.datastore.preferences.J;
import com.quizlet.remote.service.InterfaceC4775b;
import com.quizlet.remote.service.m;
import io.reactivex.rxjava3.core.q;
import io.reactivex.rxjava3.exceptions.CompositeException;
import io.reactivex.rxjava3.internal.operators.maybe.w;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Pair;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import okhttp3.n;

/* loaded from: classes3.dex */
public final class b implements q {
    public final Object a;
    public final Object b;

    public b(n cookieJar, J cookieStoreManager, kotlinx.coroutines.internal.d ioScope) {
        Intrinsics.checkNotNullParameter(cookieJar, "cookieJar");
        Intrinsics.checkNotNullParameter(cookieStoreManager, "cookieStoreManager");
        Intrinsics.checkNotNullParameter(ioScope, "ioScope");
        this.a = cookieJar;
        this.b = cookieStoreManager;
    }

    @Override // io.reactivex.rxjava3.core.q
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        ((q) this.a).a(bVar);
    }

    public void b(p0 builder) {
        Intrinsics.checkNotNullParameter(builder, "builder");
        Iterator it2 = ((ArrayList) this.b).iterator();
        while (it2.hasNext()) {
            Pair pair = (Pair) it2.next();
            kotlin.reflect.c cVar = (kotlin.reflect.c) pair.a;
            KSerializer kSerializer = (KSerializer) pair.b;
            Intrinsics.e(cVar, "null cannot be cast to non-null type kotlin.reflect.KClass<Base of kotlinx.serialization.modules.PolymorphicModuleBuilder>");
            Intrinsics.e(kSerializer, "null cannot be cast to non-null type kotlinx.serialization.KSerializer<T of kotlinx.serialization.internal.Platform_commonKt.cast>");
            p0.l(builder, (C4950i) this.a, cVar, kSerializer);
        }
    }

    public void c(C4950i subclass, KSerializer serializer) {
        Intrinsics.checkNotNullParameter(subclass, "subclass");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        ((ArrayList) this.b).add(new Pair(subclass, serializer));
    }

    @Override // io.reactivex.rxjava3.core.q
    public void onError(Throwable th) {
        try {
            Object obj = ((w) this.b).c;
            timber.log.c.a(th);
        } catch (Throwable th2) {
            x7.b(th2);
            th = new CompositeException(th, th2);
        }
        ((q) this.a).onError(th);
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        ((q) this.a).onSuccess(obj);
    }

    public b(m folderService, InterfaceC4775b bookmarkService) {
        Intrinsics.checkNotNullParameter(folderService, "folderService");
        Intrinsics.checkNotNullParameter(bookmarkService, "bookmarkService");
        this.a = folderService;
        this.b = bookmarkService;
    }

    public b(C4950i baseClass) {
        Intrinsics.checkNotNullParameter(baseClass, "baseClass");
        this.a = baseClass;
        this.b = new ArrayList();
    }

    public b(w wVar, q qVar) {
        this.b = wVar;
        this.a = qVar;
    }
}
