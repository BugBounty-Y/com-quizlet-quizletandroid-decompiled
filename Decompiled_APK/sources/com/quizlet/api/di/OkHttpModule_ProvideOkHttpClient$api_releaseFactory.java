package com.quizlet.api.di;

import com.quizlet.api.okhttp.interceptors.AcceptLanguageInterceptor;
import com.quizlet.api.okhttp.interceptors.AppSessionInterceptor;
import com.quizlet.api.okhttp.interceptors.AuthorizationInterceptor;
import com.quizlet.api.okhttp.interceptors.BuildFlavorInterceptorProvider;
import com.quizlet.api.okhttp.interceptors.DeviceIdInterceptor;
import com.quizlet.api.okhttp.interceptors.SecurityChallengeInterceptor;
import com.quizlet.api.okhttp.interceptors.UserAgentInterceptor;
import dagger.internal.c;
import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.A;
import okhttp3.n;
import okhttp3.u;
import okhttp3.z;

/* loaded from: classes2.dex */
public final class OkHttpModule_ProvideOkHttpClient$api_releaseFactory implements c {
    private final c acceptLanguageInterceptorProvider;
    private final c appSessionInterceptorProvider;
    private final c authInterceptorProvider;
    private final c buildFlavorInterceptorProvider;
    private final c cookieJarProvider;
    private final c deviceIdInterceptorProvider;
    private final c humanSecurityInterceptorProvider;
    private final OkHttpModule module;
    private final c securityChallengeInterceptorProvider;
    private final c socketFactoryProvider;
    private final c userAgentInterceptorProvider;

    public static A a(OkHttpModule okHttpModule, SocketFactory socketFactory, UserAgentInterceptor userAgentInterceptor, AcceptLanguageInterceptor acceptLanguageInterceptor, DeviceIdInterceptor deviceIdInterceptor, AppSessionInterceptor appSessionInterceptor, AuthorizationInterceptor authInterceptor, BuildFlavorInterceptorProvider buildFlavorInterceptorProvider, SecurityChallengeInterceptor securityChallengeInterceptor, u humanSecurityInterceptor, n cookieJar) {
        okHttpModule.getClass();
        Intrinsics.checkNotNullParameter(socketFactory, "socketFactory");
        Intrinsics.checkNotNullParameter(userAgentInterceptor, "userAgentInterceptor");
        Intrinsics.checkNotNullParameter(acceptLanguageInterceptor, "acceptLanguageInterceptor");
        Intrinsics.checkNotNullParameter(deviceIdInterceptor, "deviceIdInterceptor");
        Intrinsics.checkNotNullParameter(appSessionInterceptor, "appSessionInterceptor");
        Intrinsics.checkNotNullParameter(authInterceptor, "authInterceptor");
        Intrinsics.checkNotNullParameter(buildFlavorInterceptorProvider, "buildFlavorInterceptorProvider");
        Intrinsics.checkNotNullParameter(securityChallengeInterceptor, "securityChallengeInterceptor");
        Intrinsics.checkNotNullParameter(humanSecurityInterceptor, "humanSecurityInterceptor");
        Intrinsics.checkNotNullParameter(cookieJar, "cookieJar");
        z zVar = new z();
        Intrinsics.checkNotNullParameter(socketFactory, "socketFactory");
        if (socketFactory instanceof SSLSocketFactory) {
            throw new IllegalArgumentException("socketFactory instanceof SSLSocketFactory");
        }
        if (!Intrinsics.b(socketFactory, zVar.n)) {
            zVar.z = null;
        }
        zVar.n = socketFactory;
        zVar.a(acceptLanguageInterceptor);
        zVar.a(deviceIdInterceptor);
        zVar.a(appSessionInterceptor);
        zVar.a(userAgentInterceptor);
        zVar.a(authInterceptor);
        zVar.a(securityChallengeInterceptor);
        zVar.a(humanSecurityInterceptor);
        Intrinsics.checkNotNullParameter(cookieJar, "cookieJar");
        zVar.j = cookieJar;
        buildFlavorInterceptorProvider.a(zVar);
        return new A(zVar);
    }

    @Override // javax.inject.a
    public A get() {
        return a(this.module, (SocketFactory) this.socketFactoryProvider.get(), (UserAgentInterceptor) this.userAgentInterceptorProvider.get(), (AcceptLanguageInterceptor) this.acceptLanguageInterceptorProvider.get(), (DeviceIdInterceptor) this.deviceIdInterceptorProvider.get(), (AppSessionInterceptor) this.appSessionInterceptorProvider.get(), (AuthorizationInterceptor) this.authInterceptorProvider.get(), (BuildFlavorInterceptorProvider) this.buildFlavorInterceptorProvider.get(), (SecurityChallengeInterceptor) this.securityChallengeInterceptorProvider.get(), (u) this.humanSecurityInterceptorProvider.get(), (n) this.cookieJarProvider.get());
    }
}
