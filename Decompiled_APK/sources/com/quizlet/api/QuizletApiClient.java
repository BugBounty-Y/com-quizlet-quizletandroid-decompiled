package com.quizlet.api;

import android.os.Build;
import com.amazon.device.ads.DtbConstants;
import com.quizlet.api.model.AddPasswordRequest;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.model.ChangeEmailRequest;
import com.quizlet.api.model.ChangePasswordRequest;
import com.quizlet.api.model.ChangeUsernameRequest;
import com.quizlet.api.model.DataWrapper;
import com.quizlet.api.model.JoinClassData;
import com.quizlet.api.model.JoinClassRequest;
import com.quizlet.api.model.LanguageSuggestionRequest;
import com.quizlet.api.model.ReauthenticationRequest;
import com.quizlet.api.model.SubscriptionRequest;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.G1;
import io.reactivex.rxjava3.core.p;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.A;
import okhttp3.E;
import okhttp3.s;
import okhttp3.y;
import org.jetbrains.annotations.NotNull;
import retrofit2.AbstractC5180e;
import retrofit2.AbstractC5185j;
import retrofit2.HttpException;
import retrofit2.K;

@Metadata
/* loaded from: classes2.dex */
public final class QuizletApiClient implements IQuizletApiClient {

    @NotNull
    private final QuizletApi api;

    public QuizletApiClient(s baseUrl, A okHttpClient, AbstractC5180e adapter, AbstractC5185j converter) {
        Intrinsics.checkNotNullParameter(baseUrl, "baseUrl");
        Intrinsics.checkNotNullParameter(okHttpClient, "okHttpClient");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(converter, "converter");
        com.quizlet.data.repository.explanations.textbook.a aVar = new com.quizlet.data.repository.explanations.textbook.a(8);
        aVar.d(baseUrl);
        ArrayList arrayList = (ArrayList) aVar.d;
        Objects.requireNonNull(adapter, "factory == null");
        arrayList.add(adapter);
        aVar.b(converter);
        Objects.requireNonNull(okHttpClient, "client == null");
        aVar.a = okHttpClient;
        Object objB = aVar.e().b(QuizletApi.class);
        Intrinsics.checkNotNullExpressionValue(objB, "create(...)");
        this.api = (QuizletApi) objB;
    }

    public static final p C(QuizletApiClient quizletApiClient, K k) {
        quizletApiClient.getClass();
        return k.a.d() ? p.f(k) : p.d(new HttpException(k));
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g A(String str, String prefix, long j, long j2, String str2, String str3, String str4) {
        Intrinsics.checkNotNullParameter(prefix, "prefix");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.p(str, prefix, Long.valueOf(j), Long.valueOf(j2), str2, str3, str4, 3, 2).e(new i(this, 2));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g B(y body) {
        Intrinsics.checkNotNullParameter(body, "body");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.u(body).e(new b(this, 0));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g a(Map body) {
        Intrinsics.checkNotNullParameter(body, "body");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.a(body).e(new e(this, 1));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g b(String url) {
        Intrinsics.checkNotNullParameter(url, "url");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.b(url).e(new d(this, 2));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g c(ReauthenticationRequest body) {
        Intrinsics.checkNotNullParameter(body, "body");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.c(body).e(new c(this, 2));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g d(String code) {
        Intrinsics.checkNotNullParameter(code, "code");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.d(code).e(new g(this, 2));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g e() {
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.e().e(new h(this, 1));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g f(ChangeEmailRequest body) {
        Intrinsics.checkNotNullParameter(body, "body");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.f(body).e(new c(this, 0));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g g(Map body) {
        Intrinsics.checkNotNullParameter(body, "body");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.g(body).e(new i(this, 0));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    @NotNull
    public p<K<ApiThreeWrapper<DataWrapper>>> getProfileImages() {
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.v().e(new d(this, 1));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g h(SubscriptionRequest body) {
        Intrinsics.checkNotNullParameter(body, "body");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.h(body).e(new f(this, 2));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g i() {
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.i().e(new h(this, 0));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g j(Map body) {
        Intrinsics.checkNotNullParameter(body, "body");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.j(body).e(new a(this, 1));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g k(ReauthenticationRequest body) {
        Intrinsics.checkNotNullParameter(body, "body");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.k(body).e(new b(this, 2));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g l(ChangeUsernameRequest body) {
        Intrinsics.checkNotNullParameter(body, "body");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.l(body).e(new e(this, 0));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g m(AddPasswordRequest body) {
        Intrinsics.checkNotNullParameter(body, "body");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.m(body).e(new a(this, 0));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g n(long j) {
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.n(j).e(new g(this, 0));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g o(ChangePasswordRequest body) {
        Intrinsics.checkNotNullParameter(body, "body");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.o(body).e(new d(this, 0));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g p(String str, long j, long j2, String str2, String str3, String str4) {
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.z(str, Long.valueOf(j), Long.valueOf(j2), str2, str3, str4, 3, 2).e(new b(this, 3));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g q(E body) {
        Intrinsics.checkNotNullParameter(body, "body");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.A(body).e(new i(this, 1));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g r(long j, long j2, String strings) {
        Intrinsics.checkNotNullParameter(strings, "strings");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.y(new LanguageSuggestionRequest(strings, Long.valueOf(j), 1, Long.valueOf(j2))).e(new a(this, 3));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g s(String email) {
        Intrinsics.checkNotNullParameter(email, "email");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.B(U.b(new Pair("email", email))).e(new c(this, 1));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g t() {
        String release = Build.VERSION.RELEASE;
        Intrinsics.checkNotNullParameter(DtbConstants.NATIVE_OS_NAME, "platform");
        Intrinsics.checkNotNullParameter(release, "release");
        Intrinsics.checkNotNullParameter("9.34.3", "versionName");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.w(DtbConstants.NATIVE_OS_NAME, release, 2601637, "9.34.3").e(new f(this, 0));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g u(E body) {
        Intrinsics.checkNotNullParameter(body, "body");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.C(body).e(new e(this, 2));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g v(y body) {
        Intrinsics.checkNotNullParameter(body, "body");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.r(body).e(new h(this, 2));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g w(String email) {
        Intrinsics.checkNotNullParameter(email, "email");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.s(U.b(new Pair("email", email))).e(new b(this, 1));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g x(long j, G1 studyableType, A1 mode) {
        Intrinsics.checkNotNullParameter(studyableType, "studyableType");
        Intrinsics.checkNotNullParameter(mode, "mode");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.x(j, studyableType.b(), mode.a(), "user").e(new f(this, 1));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g y(long j, long j2, String autoJoinCode, int i) {
        Intrinsics.checkNotNullParameter(autoJoinCode, "autoJoinCode");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.t(new JoinClassRequest(kotlin.collections.A.b(new JoinClassData(j, j2, autoJoinCode, i)))).e(new g(this, 1));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }

    @Override // com.quizlet.api.IQuizletApiClient
    public final io.reactivex.rxjava3.internal.operators.single.g z(LinkedHashMap body) {
        Intrinsics.checkNotNullParameter(body, "body");
        io.reactivex.rxjava3.internal.operators.single.g gVarE = this.api.q(body).e(new a(this, 2));
        Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
        return gVarE;
    }
}
