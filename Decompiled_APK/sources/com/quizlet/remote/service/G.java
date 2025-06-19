package com.quizlet.remote.service;

import com.quizlet.remote.model.base.ApiError;
import com.quizlet.remote.model.base.ApiErrorWrapper;
import com.squareup.moshi.JsonEncodingException;
import java.lang.annotation.Annotation;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.I;
import retrofit2.AbstractC5180e;
import retrofit2.C5184i;
import retrofit2.HttpException;
import retrofit2.InterfaceC5179d;
import retrofit2.InterfaceC5181f;
import retrofit2.InterfaceC5186k;
import retrofit2.K;
import retrofit2.L;
import retrofit2.M;
import retrofit2.S;

/* loaded from: classes3.dex */
public final class G extends AbstractC5180e {
    public final /* synthetic */ int a = 1;
    public final Object b;

    public G(androidx.core.os.d dVar) {
        this.b = dVar;
    }

    public static final Throwable b(G g, L l, Throwable th) {
        K k;
        I i;
        ApiErrorWrapper apiErrorWrapper;
        g.getClass();
        if (!(th instanceof HttpException)) {
            return th;
        }
        try {
            HttpException httpException = (HttpException) th;
            K k2 = httpException.c;
            if ((k2 != null && k2.a.d()) || (k = httpException.c) == null || (i = k.c) == null) {
                apiErrorWrapper = null;
            } else {
                InterfaceC5186k interfaceC5186kD = l.d(ApiErrorWrapper.class, new Annotation[0]);
                Intrinsics.checkNotNullExpressionValue(interfaceC5186kD, "responseBodyConverter(...)");
                apiErrorWrapper = (ApiErrorWrapper) interfaceC5186kD.convert(i);
            }
            ApiError apiError = apiErrorWrapper != null ? apiErrorWrapper.a : null;
            String str = ((HttpException) th).b;
            Intrinsics.checkNotNullExpressionValue(str, "message(...)");
            return new NetworkException(apiError, str, th);
        } catch (JsonEncodingException e) {
            return e;
        }
    }

    @Override // retrofit2.AbstractC5180e
    public final InterfaceC5181f a(Type returnType, Annotation[] annotations, L retrofit) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(returnType, "returnType");
                Intrinsics.checkNotNullParameter(annotations, "annotations");
                Intrinsics.checkNotNullParameter(retrofit, "retrofit");
                InterfaceC5181f interfaceC5181fA = ((C5184i) this.b).a(returnType, annotations, retrofit);
                Intrinsics.e(interfaceC5181fA, "null cannot be cast to non-null type retrofit2.CallAdapter<kotlin.Any, kotlin.Any>");
                return new com.quizlet.data.repository.folderset.c(this, retrofit, (retrofit2.adapter.rxjava3.e) interfaceC5181fA);
            default:
                if (S.i(returnType) != InterfaceC5179d.class) {
                    return null;
                }
                if (returnType instanceof ParameterizedType) {
                    return new com.quizlet.remote.model.progress.e(S.h(0, (ParameterizedType) returnType), S.m(annotations, M.class) ? null : (androidx.core.os.d) this.b);
                }
                throw new IllegalArgumentException("Call return type must be parameterized as Call<Foo> or Call<? extends Foo>");
        }
    }

    public G(C5184i rxJavaCallAdapterFactory) {
        Intrinsics.checkNotNullParameter(rxJavaCallAdapterFactory, "rxJavaCallAdapterFactory");
        this.b = rxJavaCallAdapterFactory;
    }
}
