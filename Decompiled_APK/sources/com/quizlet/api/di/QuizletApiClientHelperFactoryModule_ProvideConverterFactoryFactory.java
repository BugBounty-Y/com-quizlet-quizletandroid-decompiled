package com.quizlet.api.di;

import com.fasterxml.jackson.databind.ObjectMapper;
import dagger.internal.c;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.w;
import retrofit2.AbstractC5185j;
import retrofit2.converter.jackson.a;

/* loaded from: classes2.dex */
public final class QuizletApiClientHelperFactoryModule_ProvideConverterFactoryFactory implements c {
    private final c mapperProvider;

    public static a a(ObjectMapper mapper) {
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        if (mapper == null) {
            w wVar = a.c;
            throw new NullPointerException("mapper == null");
        }
        w wVar2 = a.c;
        if (wVar2 == null) {
            throw new NullPointerException("mediaType == null");
        }
        a aVar = new a(mapper, wVar2);
        Intrinsics.checkNotNullExpressionValue(aVar, "create(...)");
        return aVar;
    }

    @Override // javax.inject.a
    public AbstractC5185j get() {
        return a((ObjectMapper) this.mapperProvider.get());
    }
}
