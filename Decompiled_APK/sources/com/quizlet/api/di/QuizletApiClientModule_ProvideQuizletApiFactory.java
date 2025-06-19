package com.quizlet.api.di;

import com.quizlet.api.IQuizletApiClient;
import com.quizlet.api.QuizletApiClient;
import dagger.internal.c;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.A;
import okhttp3.s;
import retrofit2.AbstractC5180e;
import retrofit2.AbstractC5185j;

/* loaded from: classes2.dex */
public final class QuizletApiClientModule_ProvideQuizletApiFactory implements c {
    private final c baseUrlProvider;
    private final c callAdapterProvider;
    private final c jsonConverterProvider;
    private final c okHttpClientProvider;

    @Override // javax.inject.a
    public IQuizletApiClient get() {
        s baseUrl = (s) this.baseUrlProvider.get();
        A okHttpClient = (A) this.okHttpClientProvider.get();
        AbstractC5180e callAdapter = (AbstractC5180e) this.callAdapterProvider.get();
        AbstractC5185j jsonConverter = (AbstractC5185j) this.jsonConverterProvider.get();
        Intrinsics.checkNotNullParameter(baseUrl, "baseUrl");
        Intrinsics.checkNotNullParameter(okHttpClient, "okHttpClient");
        Intrinsics.checkNotNullParameter(callAdapter, "callAdapter");
        Intrinsics.checkNotNullParameter(jsonConverter, "jsonConverter");
        return new QuizletApiClient(baseUrl, okHttpClient, callAdapter, jsonConverter);
    }
}
