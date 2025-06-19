package com.quizlet.login.oldlogin;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.work.impl.model.v;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.login.common.exception.BlockedByCaptchaException;
import com.quizlet.login.common.exception.LoginException;
import com.quizlet.login.recovery.data.ScreenState;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class o extends com.quizlet.viewmodel.b {
    public final io.ktor.client.plugins.api.d c;
    public final io.reactivex.rxjava3.core.o d;
    public final io.reactivex.rxjava3.core.o e;
    public final com.google.android.gms.internal.appset.e f;
    public final io.ktor.client.plugins.api.d g;
    public final androidx.work.impl.model.l h;
    public final com.quizlet.login.common.util.b i;
    public final com.quizlet.qutils.string.c j;
    public final com.quizlet.login.common.interactors.d k;
    public final com.quizlet.data.interactor.achievements.f l;
    public final com.google.firebase.crashlytics.internal.settings.b m;
    public final com.google.mlkit.vision.documentscanner.internal.c n;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e o;
    public final v p;
    public final com.google.firebase.crashlytics.internal.common.j q;
    public final boolean r;
    public final Y s;
    public final X t;
    public final X u;
    public boolean v;
    public String w;
    public String x;

    public o(m0 savedStateHandle, io.ktor.client.plugins.api.d loginSignUpUserManager, io.reactivex.rxjava3.core.o networkScheduler, io.reactivex.rxjava3.core.o mainThreadScheduler, com.google.android.gms.internal.appset.e logger, io.ktor.client.plugins.api.d apiClient, androidx.work.impl.model.l signUpRequestParentEmailFeature, com.quizlet.login.common.util.b ageUtil, com.quizlet.login.common.interactors.d deepLinkRouter, com.quizlet.data.interactor.achievements.f isAnySubscriptionAvailableUseCase, com.google.firebase.crashlytics.internal.settings.b requireEmailConfirmationFeature, com.google.mlkit.vision.documentscanner.internal.c saveConfirmationWallEmailUseCase, com.quizlet.data.repository.folderwithcreatorinclass.e qIncentivesUseCase, v onboardingQPlusUpsellUseCase, com.google.firebase.crashlytics.internal.common.j onboardingELLUseCase) {
        com.quizlet.qutils.string.c emailUtil = com.quizlet.qutils.string.c.a;
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(loginSignUpUserManager, "loginSignUpUserManager");
        Intrinsics.checkNotNullParameter(networkScheduler, "networkScheduler");
        Intrinsics.checkNotNullParameter(mainThreadScheduler, "mainThreadScheduler");
        Intrinsics.checkNotNullParameter(logger, "logger");
        Intrinsics.checkNotNullParameter(apiClient, "apiClient");
        Intrinsics.checkNotNullParameter(signUpRequestParentEmailFeature, "signUpRequestParentEmailFeature");
        Intrinsics.checkNotNullParameter(ageUtil, "ageUtil");
        Intrinsics.checkNotNullParameter(emailUtil, "emailUtil");
        Intrinsics.checkNotNullParameter(deepLinkRouter, "deepLinkRouter");
        Intrinsics.checkNotNullParameter(isAnySubscriptionAvailableUseCase, "isAnySubscriptionAvailableUseCase");
        Intrinsics.checkNotNullParameter(requireEmailConfirmationFeature, "requireEmailConfirmationFeature");
        Intrinsics.checkNotNullParameter(saveConfirmationWallEmailUseCase, "saveConfirmationWallEmailUseCase");
        Intrinsics.checkNotNullParameter(qIncentivesUseCase, "qIncentivesUseCase");
        Intrinsics.checkNotNullParameter(onboardingQPlusUpsellUseCase, "onboardingQPlusUpsellUseCase");
        Intrinsics.checkNotNullParameter(onboardingELLUseCase, "onboardingELLUseCase");
        this.c = loginSignUpUserManager;
        this.d = networkScheduler;
        this.e = mainThreadScheduler;
        this.f = logger;
        this.g = apiClient;
        this.h = signUpRequestParentEmailFeature;
        this.i = ageUtil;
        this.j = emailUtil;
        this.k = deepLinkRouter;
        this.l = isAnySubscriptionAvailableUseCase;
        this.m = requireEmailConfirmationFeature;
        this.n = saveConfirmationWallEmailUseCase;
        this.o = qIncentivesUseCase;
        this.p = onboardingQPlusUpsellUseCase;
        this.q = onboardingELLUseCase;
        Boolean bool = (Boolean) savedStateHandle.a("shouldLaunchPromptParentEmailFlow");
        boolean zBooleanValue = bool != null ? bool.booleanValue() : false;
        HashMap map = (HashMap) savedStateHandle.a("parentEmailRequestParams");
        String authProvider = (String) savedStateHandle.a("parentEmailAuthProvider");
        b bVar = (b) savedStateHandle.a("parentEmailRequestType");
        Boolean bool2 = (Boolean) savedStateHandle.a("shouldLaunchBirthdayFlow");
        boolean zBooleanValue2 = bool2 != null ? bool2.booleanValue() : false;
        String str = (String) savedStateHandle.a("birthdayAuthToken");
        String authProvider2 = (String) savedStateHandle.a("birthdayAuthProvider");
        Boolean bool3 = (Boolean) savedStateHandle.a("shouldSkipUpsell");
        this.r = bool3 != null ? bool3.booleanValue() : false;
        this.s = new Y();
        X x = new X(1);
        this.t = x;
        this.u = new X(1);
        this.w = "email";
        EventLogger eventLogger = (EventLogger) logger.b;
        if (zBooleanValue && map != null && authProvider != null && bVar != null) {
            Intrinsics.checkNotNullParameter(authProvider, "authProvider");
            EventLoggerExt.a(eventLogger, "authentication_parent_email_request", new com.quizlet.features.notes.logging.b(authProvider, true));
            x.j(new LaunchParentEmailFragment(map, authProvider, bVar));
        }
        if (zBooleanValue2 && str != null && authProvider2 != null) {
            this.w = authProvider2;
            boolean z = this.v;
            Intrinsics.checkNotNullParameter(authProvider2, "authProvider");
            eventLogger.e(authProvider2, z);
            x.j(new LaunchBirthdayFragment(str, this.w));
        }
        E.A(p0.j(this), null, null, new j(this, null), 3);
    }

    public final void B(com.quizlet.login.authentication.data.i iVar, String str) {
        boolean z = iVar instanceof com.quizlet.login.authentication.data.d;
        X x = this.u;
        if (z) {
            if (((com.quizlet.login.authentication.data.d) iVar).a) {
                x.j(com.quizlet.login.authentication.h.c);
                return;
            }
            return;
        }
        if (iVar instanceof com.quizlet.login.authentication.data.l) {
            com.quizlet.login.authentication.data.l lVar = (com.quizlet.login.authentication.data.l) iVar;
            E.A(p0.j(this), null, null, new i(lVar.b, false, this, lVar.a, null), 3);
            return;
        }
        if (iVar instanceof com.quizlet.login.authentication.data.m) {
            com.quizlet.login.authentication.data.m mVar = (com.quizlet.login.authentication.data.m) iVar;
            E.A(p0.j(this), null, null, new i(mVar.b, true, this, mVar.a, null), 3);
            return;
        }
        boolean z2 = iVar instanceof com.quizlet.login.authentication.data.k;
        X x2 = this.t;
        if (z2) {
            String str2 = ((com.quizlet.login.authentication.data.k) iVar).a;
            String authProvider = this.w;
            boolean z3 = this.v;
            com.google.android.gms.internal.appset.e eVar = this.f;
            eVar.getClass();
            Intrinsics.checkNotNullParameter(authProvider, "authProvider");
            ((EventLogger) eVar.b).e(authProvider, z3);
            x2.j(new LaunchBirthdayFragment(str2, this.w));
            return;
        }
        if (iVar instanceof com.quizlet.login.authentication.data.n) {
            x.j(new com.quizlet.login.authentication.j(((com.quizlet.login.authentication.data.n) iVar).a));
            return;
        }
        if (iVar instanceof com.quizlet.login.authentication.data.b) {
            String str3 = ((com.quizlet.login.authentication.data.b) iVar).a;
            if (str3 != null) {
                x.j(new com.quizlet.login.authentication.b(str3));
            } else {
                x.j(com.quizlet.login.authentication.h.c);
            }
            timber.log.c.a.h(new LoginException(AbstractC0147y.d("ANDROID-5817: onApiThreeError with error: ", str3)));
            return;
        }
        if (iVar instanceof com.quizlet.login.authentication.data.c) {
            x.j(com.quizlet.login.authentication.c.c);
            timber.log.c.a.e(new BlockedByCaptchaException(0));
            return;
        }
        if (iVar instanceof com.quizlet.login.authentication.data.j) {
            x2.j(new a(ScreenState.MultipleAccountsExist.a));
            return;
        }
        if (iVar instanceof com.quizlet.login.authentication.data.h) {
            x.j(com.quizlet.login.authentication.i.c);
            timber.log.a aVar = timber.log.c.a;
            Intrinsics.checkNotNullParameter("Log-in blocked by invalid region.", "message");
            Intrinsics.checkNotNullParameter("Log-in blocked by invalid region.", "message");
            aVar.e(new h("Log-in blocked by invalid region."));
            return;
        }
        if (iVar instanceof com.quizlet.login.authentication.data.a) {
            com.quizlet.login.authentication.data.f fVar = ((com.quizlet.login.authentication.data.a) iVar).a;
            x2.j(new a(fVar == null ? ScreenState.UnknownAccountExists.a : new ScreenState.KnownAccountExists(fVar.a, fVar.b, fVar.c, fVar.d)));
        } else if (iVar instanceof com.quizlet.login.authentication.data.e) {
            E.A(p0.j(this), null, null, new m(str, this, null), 3);
        } else {
            if (!(iVar instanceof com.quizlet.login.authentication.data.g)) {
                throw new NoWhenBranchMatchedException();
            }
            x.j(com.quizlet.login.authentication.g.c);
        }
    }

    public final void C(LinkedHashMap request, boolean z, String str) {
        this.v = z;
        this.w = str;
        timber.log.c.a.g("ANDROID-5817: AuthManager.oauthExtraInfo", new Object[0]);
        io.ktor.client.plugins.api.d dVar = this.g;
        dVar.getClass();
        Intrinsics.checkNotNullParameter(request, "request");
        io.reactivex.rxjava3.internal.operators.single.g gVarG = ((IQuizletApiClient) dVar.b).z(request).g(new com.quizlet.data.interactor.course.a(dVar, 22));
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        io.reactivex.rxjava3.internal.observers.e eVarF = F(gVarG, null, (String) request.get("email"));
        Intrinsics.checkNotNullParameter(eVarF, "<this>");
        A(eVarF);
        this.f.r(this.w, z);
    }

    public final void D(String userIdentifier, String password) {
        Intrinsics.checkNotNullParameter(userIdentifier, "userIdentifier");
        Intrinsics.checkNotNullParameter(password, "password");
        this.v = false;
        this.x = password;
        this.w = "email";
        Map mapF = V.f(new Pair("username", userIdentifier), new Pair(DBStudySetFields.Names.PASSWORD, password), new Pair("state", UUID.randomUUID().toString()));
        timber.log.c.a.g("ANDROID-5817: AuthManager.quizletLogin", new Object[0]);
        String str = (String) mapF.get("username");
        io.reactivex.rxjava3.internal.operators.single.g gVarJ = this.g.j(str, mapF);
        String str2 = str == null ? "" : str;
        this.j.getClass();
        F(gVarJ, str, com.quizlet.qutils.string.c.c(str2) ? str : null);
        this.f.r("email", this.v);
    }

    public final void E(LinkedHashMap linkedHashMap) {
        this.v = true;
        this.w = "email";
        timber.log.c.a.g("ANDROID-5817: AuthManager.quizletSignup", new Object[0]);
        io.reactivex.rxjava3.internal.observers.e eVarF = F(this.g.k(linkedHashMap), null, (String) linkedHashMap.get("email"));
        Intrinsics.checkNotNullParameter(eVarF, "<this>");
        A(eVarF);
        this.f.r("email", this.v);
    }

    public final io.reactivex.rxjava3.internal.observers.e F(io.reactivex.rxjava3.internal.operators.single.g gVar, String str, String str2) {
        io.reactivex.rxjava3.internal.observers.e eVarI = new io.reactivex.rxjava3.internal.operators.single.e(new io.reactivex.rxjava3.internal.operators.single.d(gVar.l(this.d).h(this.e), new com.quizlet.analytics.marketing.e(this, 17), 1), new com.quizlet.eventlogger.e(this, 16), 0).i(new com.quizlet.billing.manager.b(8, this, str2), new com.quizlet.features.setpage.utils.setpermissions.e(this, str, str2, 1));
        Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
        return eVarI;
    }
}
