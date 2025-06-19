package com.quizlet.quizletandroid.ui.login;

import android.app.Activity;
import android.content.ComponentCallbacks2;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.lifecycle.Z;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.D6;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.firebase.perf.metrics.Trace;
import com.quizlet.features.emailconfirmation.ui.activities.MagicLinkConfirmationActivity;
import com.quizlet.login.oldlogin.LaunchBirthdayFragment;
import com.quizlet.login.oldlogin.LaunchParentEmailFragment;
import com.quizlet.login.recovery.data.ScreenState;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4598b;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import com.quizlet.quizletandroid.ui.common.views.LoadingIndicatorView;
import com.quizlet.quizletandroid.ui.login.accountrecovery.AccountRecoveryModalFragment;
import com.quizlet.uicommon.ui.common.dialogs.QAlertDialogFragment;
import com.quizlet.upgrade.ui.activity.UpgradeActivity;
import java.util.HashMap;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class n extends com.quizlet.baseui.base.f implements dagger.hilt.internal.b, dagger.hilt.android.internal.migration.a, com.quizlet.features.consent.onetrust.b {
    public C4636c l;
    public com.quizlet.login.oldlogin.o m;
    public com.quizlet.login.authentication.login.a n;
    public volatile dagger.hilt.android.internal.managers.b o;
    public final Object p = new Object();
    public boolean q = false;

    public n() {
        addOnContextAvailableListener(new com.quizlet.quizletandroid.ui.group.i((OldSignupActivity) this, 7));
    }

    @Override // com.quizlet.baseui.base.b
    public final void I(boolean z) {
        ((C4598b) this.k).d.setLoadingText(getString(R.string.login_progress_signing_in));
        ((C4598b) this.k).d.setVisibility(z ? 0 : 8);
        ((C4598b) this.k).b.setVisibility(z ? 8 : 0);
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        View viewInflate = getLayoutInflater().inflate(R.layout.accounts_activity, (ViewGroup) null, false);
        int i = R.id.account_login_signup_close_button;
        ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.account_login_signup_close_button, viewInflate);
        if (imageView != null) {
            i = R.id.account_login_signup_content;
            if (((LinearLayout) AbstractC3375o2.c(R.id.account_login_signup_content, viewInflate)) != null) {
                i = R.id.account_sliding_layer_container;
                if (((ScrollView) AbstractC3375o2.c(R.id.account_sliding_layer_container, viewInflate)) != null) {
                    i = R.id.fragment_container;
                    FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.fragment_container, viewInflate);
                    if (frameLayout != null) {
                        i = R.id.loading_indicator;
                        LoadingIndicatorView loadingIndicatorView = (LoadingIndicatorView) AbstractC3375o2.c(R.id.loading_indicator, viewInflate);
                        if (loadingIndicatorView != null) {
                            i = R.id.topbar;
                            FrameLayout frameLayout2 = (FrameLayout) AbstractC3375o2.c(R.id.topbar, viewInflate);
                            if (frameLayout2 != null) {
                                return new C4598b((LinearLayout) viewInflate, imageView, frameLayout, loadingIndicatorView, frameLayout2);
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final dagger.hilt.android.internal.managers.b O() {
        if (this.o == null) {
            synchronized (this.p) {
                try {
                    if (this.o == null) {
                        this.o = new dagger.hilt.android.internal.managers.b((Activity) this);
                    }
                } finally {
                }
            }
        }
        return this.o;
    }

    public final void P(Bundle bundle) {
        Trace traceA = com.google.firebase.perf.b.a("SocialSignupActivity_onCreate_trace");
        super.onCreate(bundle);
        androidx.activity.v.a(this);
        AbstractC3188k6.a(((C4598b) this.k).a);
        com.quizlet.login.oldlogin.o oVar = (com.quizlet.login.oldlogin.o) D6.g(this, com.quizlet.login.oldlogin.o.class);
        this.m = oVar;
        final int i = 0;
        oVar.u.f(this, new Z(this) { // from class: com.quizlet.quizletandroid.ui.login.A
            public final /* synthetic */ n b;

            {
                this.b = this;
            }

            @Override // androidx.lifecycle.Z
            public final void a(Object obj) {
                String str;
                n context = this.b;
                switch (i) {
                    case 0:
                        com.quizlet.login.authentication.k kVar = (com.quizlet.login.authentication.k) obj;
                        String message = kVar.a(context);
                        Intrinsics.checkNotNullParameter(message, "message");
                        String text = context.getString(R.string.OK);
                        B b = new B(0);
                        Intrinsics.checkNotNullParameter(text, "text");
                        Intrinsics.checkNotNullParameter(context, "context");
                        com.quizlet.qutils.string.g gVar = kVar.b;
                        String title = gVar != null ? gVar.a(context) : null;
                        if (title != null) {
                            Intrinsics.checkNotNullParameter(title, "title");
                            str = title;
                        } else {
                            str = null;
                        }
                        String str2 = QAlertDialogFragment.t;
                        com.quizlet.uicommon.ui.common.dialogs.h.a(new com.quizlet.uicommon.ui.common.dialogs.i(new QAlertDialogFragment.DialogData(message, str, text, null, true, null), b, null, null)).O(context.getSupportFragmentManager(), QAlertDialogFragment.t);
                        break;
                    case 1:
                        context.I(((Boolean) obj).booleanValue());
                        break;
                    default:
                        com.quizlet.login.oldlogin.c cVar = (com.quizlet.login.oldlogin.c) obj;
                        if (!(cVar instanceof LaunchBirthdayFragment)) {
                            if (!(cVar instanceof com.quizlet.login.oldlogin.d)) {
                                if (!(cVar instanceof com.quizlet.login.oldlogin.f)) {
                                    if (!(cVar instanceof com.quizlet.login.oldlogin.a)) {
                                        if (!(cVar instanceof LaunchParentEmailFragment)) {
                                            if (cVar instanceof com.quizlet.login.oldlogin.e) {
                                                context.l.getClass();
                                                Intrinsics.checkNotNullParameter(context, "activity");
                                                String str3 = MagicLinkConfirmationActivity.r;
                                                Intrinsics.checkNotNullParameter(context, "context");
                                                context.startActivity(new Intent(context, (Class<?>) MagicLinkConfirmationActivity.class));
                                                context.finish();
                                                break;
                                            }
                                        } else {
                                            LaunchParentEmailFragment launchParentEmailFragment = (LaunchParentEmailFragment) cVar;
                                            String str4 = ParentEmailFragment.n;
                                            HashMap pendingRequest = launchParentEmailFragment.a;
                                            Intrinsics.checkNotNullParameter(pendingRequest, "pendingRequest");
                                            String authProvider = launchParentEmailFragment.b;
                                            Intrinsics.checkNotNullParameter(authProvider, "authProvider");
                                            com.quizlet.login.oldlogin.b requestType = launchParentEmailFragment.c;
                                            Intrinsics.checkNotNullParameter(requestType, "requestType");
                                            ParentEmailFragment parentEmailFragment = new ParentEmailFragment();
                                            parentEmailFragment.setArguments(AbstractC3206m6.a(new Pair("pendingRequest", new HashMap(pendingRequest)), new Pair("authProvider", authProvider), new Pair("isSignUp", Boolean.TRUE), new Pair("requestType", requestType)));
                                            AbstractC1136h0 supportFragmentManager = context.getSupportFragmentManager();
                                            supportFragmentManager.getClass();
                                            C1121a c1121a = new C1121a(supportFragmentManager);
                                            c1121a.l(R.id.fragment_container, parentEmailFragment, null);
                                            c1121a.h(true, true);
                                            ((C4598b) context.k).e.setVisibility(8);
                                            context.I(false);
                                            break;
                                        }
                                    } else {
                                        ScreenState existingAccountInfo = ((com.quizlet.login.oldlogin.a) cVar).a;
                                        String str5 = AccountRecoveryModalFragment.I;
                                        Intrinsics.checkNotNullParameter(existingAccountInfo, "existingAccountInfo");
                                        AccountRecoveryModalFragment accountRecoveryModalFragment = new AccountRecoveryModalFragment();
                                        Bundle bundle2 = new Bundle();
                                        bundle2.putParcelable("existing_account_info_arg", existingAccountInfo);
                                        accountRecoveryModalFragment.setArguments(bundle2);
                                        accountRecoveryModalFragment.O(context.getSupportFragmentManager(), AccountRecoveryModalFragment.I);
                                        break;
                                    }
                                } else {
                                    boolean z = ((com.quizlet.login.oldlogin.f) cVar).a;
                                    context.l.getClass();
                                    Intrinsics.checkNotNullParameter(context, "activity");
                                    String str6 = UpgradeActivity.v;
                                    Intent intentI = AbstractC3242q6.i(context, OldSignupActivity.r, com.quizlet.features.infra.models.upgrade.a.f);
                                    intentI.setAction(z ? "require_email_confirmation" : context.getIntent().getAction());
                                    context.startActivity(intentI);
                                    context.finish();
                                    break;
                                }
                            } else {
                                boolean z2 = ((com.quizlet.login.oldlogin.d) cVar).a;
                                C4636c c4636c = context.l;
                                c4636c.getClass();
                                Intrinsics.checkNotNullParameter(context, "activity");
                                if (z2) {
                                    context.getIntent().setAction("require_email_confirmation");
                                }
                                ((com.quizlet.quizletandroid.util.g) c4636c.b).getClass();
                                com.quizlet.quizletandroid.util.g.a(context, null);
                                break;
                            }
                        } else {
                            LaunchBirthdayFragment launchBirthdayFragment = (LaunchBirthdayFragment) cVar;
                            String oauthToken = launchBirthdayFragment.a;
                            String str7 = UserBirthdayFragment.w;
                            Intrinsics.checkNotNullParameter(oauthToken, "oauthToken");
                            String authProvider2 = launchBirthdayFragment.b;
                            Intrinsics.checkNotNullParameter(authProvider2, "authProvider");
                            UserBirthdayFragment userBirthdayFragment = new UserBirthdayFragment();
                            Bundle bundle3 = new Bundle();
                            bundle3.putString("oauthToken", oauthToken);
                            bundle3.putString("authProvider", authProvider2);
                            bundle3.putBoolean("isSignUp", true);
                            userBirthdayFragment.setArguments(bundle3);
                            AbstractC1136h0 supportFragmentManager2 = context.getSupportFragmentManager();
                            supportFragmentManager2.getClass();
                            C1121a c1121a2 = new C1121a(supportFragmentManager2);
                            c1121a2.l(R.id.fragment_container, userBirthdayFragment, null);
                            c1121a2.h(true, true);
                            context.I(false);
                            break;
                        }
                        break;
                }
            }
        });
        final int i2 = 1;
        this.m.s.f(this, new Z(this) { // from class: com.quizlet.quizletandroid.ui.login.A
            public final /* synthetic */ n b;

            {
                this.b = this;
            }

            @Override // androidx.lifecycle.Z
            public final void a(Object obj) {
                String str;
                n context = this.b;
                switch (i2) {
                    case 0:
                        com.quizlet.login.authentication.k kVar = (com.quizlet.login.authentication.k) obj;
                        String message = kVar.a(context);
                        Intrinsics.checkNotNullParameter(message, "message");
                        String text = context.getString(R.string.OK);
                        B b = new B(0);
                        Intrinsics.checkNotNullParameter(text, "text");
                        Intrinsics.checkNotNullParameter(context, "context");
                        com.quizlet.qutils.string.g gVar = kVar.b;
                        String title = gVar != null ? gVar.a(context) : null;
                        if (title != null) {
                            Intrinsics.checkNotNullParameter(title, "title");
                            str = title;
                        } else {
                            str = null;
                        }
                        String str2 = QAlertDialogFragment.t;
                        com.quizlet.uicommon.ui.common.dialogs.h.a(new com.quizlet.uicommon.ui.common.dialogs.i(new QAlertDialogFragment.DialogData(message, str, text, null, true, null), b, null, null)).O(context.getSupportFragmentManager(), QAlertDialogFragment.t);
                        break;
                    case 1:
                        context.I(((Boolean) obj).booleanValue());
                        break;
                    default:
                        com.quizlet.login.oldlogin.c cVar = (com.quizlet.login.oldlogin.c) obj;
                        if (!(cVar instanceof LaunchBirthdayFragment)) {
                            if (!(cVar instanceof com.quizlet.login.oldlogin.d)) {
                                if (!(cVar instanceof com.quizlet.login.oldlogin.f)) {
                                    if (!(cVar instanceof com.quizlet.login.oldlogin.a)) {
                                        if (!(cVar instanceof LaunchParentEmailFragment)) {
                                            if (cVar instanceof com.quizlet.login.oldlogin.e) {
                                                context.l.getClass();
                                                Intrinsics.checkNotNullParameter(context, "activity");
                                                String str3 = MagicLinkConfirmationActivity.r;
                                                Intrinsics.checkNotNullParameter(context, "context");
                                                context.startActivity(new Intent(context, (Class<?>) MagicLinkConfirmationActivity.class));
                                                context.finish();
                                                break;
                                            }
                                        } else {
                                            LaunchParentEmailFragment launchParentEmailFragment = (LaunchParentEmailFragment) cVar;
                                            String str4 = ParentEmailFragment.n;
                                            HashMap pendingRequest = launchParentEmailFragment.a;
                                            Intrinsics.checkNotNullParameter(pendingRequest, "pendingRequest");
                                            String authProvider = launchParentEmailFragment.b;
                                            Intrinsics.checkNotNullParameter(authProvider, "authProvider");
                                            com.quizlet.login.oldlogin.b requestType = launchParentEmailFragment.c;
                                            Intrinsics.checkNotNullParameter(requestType, "requestType");
                                            ParentEmailFragment parentEmailFragment = new ParentEmailFragment();
                                            parentEmailFragment.setArguments(AbstractC3206m6.a(new Pair("pendingRequest", new HashMap(pendingRequest)), new Pair("authProvider", authProvider), new Pair("isSignUp", Boolean.TRUE), new Pair("requestType", requestType)));
                                            AbstractC1136h0 supportFragmentManager = context.getSupportFragmentManager();
                                            supportFragmentManager.getClass();
                                            C1121a c1121a = new C1121a(supportFragmentManager);
                                            c1121a.l(R.id.fragment_container, parentEmailFragment, null);
                                            c1121a.h(true, true);
                                            ((C4598b) context.k).e.setVisibility(8);
                                            context.I(false);
                                            break;
                                        }
                                    } else {
                                        ScreenState existingAccountInfo = ((com.quizlet.login.oldlogin.a) cVar).a;
                                        String str5 = AccountRecoveryModalFragment.I;
                                        Intrinsics.checkNotNullParameter(existingAccountInfo, "existingAccountInfo");
                                        AccountRecoveryModalFragment accountRecoveryModalFragment = new AccountRecoveryModalFragment();
                                        Bundle bundle2 = new Bundle();
                                        bundle2.putParcelable("existing_account_info_arg", existingAccountInfo);
                                        accountRecoveryModalFragment.setArguments(bundle2);
                                        accountRecoveryModalFragment.O(context.getSupportFragmentManager(), AccountRecoveryModalFragment.I);
                                        break;
                                    }
                                } else {
                                    boolean z = ((com.quizlet.login.oldlogin.f) cVar).a;
                                    context.l.getClass();
                                    Intrinsics.checkNotNullParameter(context, "activity");
                                    String str6 = UpgradeActivity.v;
                                    Intent intentI = AbstractC3242q6.i(context, OldSignupActivity.r, com.quizlet.features.infra.models.upgrade.a.f);
                                    intentI.setAction(z ? "require_email_confirmation" : context.getIntent().getAction());
                                    context.startActivity(intentI);
                                    context.finish();
                                    break;
                                }
                            } else {
                                boolean z2 = ((com.quizlet.login.oldlogin.d) cVar).a;
                                C4636c c4636c = context.l;
                                c4636c.getClass();
                                Intrinsics.checkNotNullParameter(context, "activity");
                                if (z2) {
                                    context.getIntent().setAction("require_email_confirmation");
                                }
                                ((com.quizlet.quizletandroid.util.g) c4636c.b).getClass();
                                com.quizlet.quizletandroid.util.g.a(context, null);
                                break;
                            }
                        } else {
                            LaunchBirthdayFragment launchBirthdayFragment = (LaunchBirthdayFragment) cVar;
                            String oauthToken = launchBirthdayFragment.a;
                            String str7 = UserBirthdayFragment.w;
                            Intrinsics.checkNotNullParameter(oauthToken, "oauthToken");
                            String authProvider2 = launchBirthdayFragment.b;
                            Intrinsics.checkNotNullParameter(authProvider2, "authProvider");
                            UserBirthdayFragment userBirthdayFragment = new UserBirthdayFragment();
                            Bundle bundle3 = new Bundle();
                            bundle3.putString("oauthToken", oauthToken);
                            bundle3.putString("authProvider", authProvider2);
                            bundle3.putBoolean("isSignUp", true);
                            userBirthdayFragment.setArguments(bundle3);
                            AbstractC1136h0 supportFragmentManager2 = context.getSupportFragmentManager();
                            supportFragmentManager2.getClass();
                            C1121a c1121a2 = new C1121a(supportFragmentManager2);
                            c1121a2.l(R.id.fragment_container, userBirthdayFragment, null);
                            c1121a2.h(true, true);
                            context.I(false);
                            break;
                        }
                        break;
                }
            }
        });
        final int i3 = 2;
        this.m.t.f(this, new Z(this) { // from class: com.quizlet.quizletandroid.ui.login.A
            public final /* synthetic */ n b;

            {
                this.b = this;
            }

            @Override // androidx.lifecycle.Z
            public final void a(Object obj) {
                String str;
                n context = this.b;
                switch (i3) {
                    case 0:
                        com.quizlet.login.authentication.k kVar = (com.quizlet.login.authentication.k) obj;
                        String message = kVar.a(context);
                        Intrinsics.checkNotNullParameter(message, "message");
                        String text = context.getString(R.string.OK);
                        B b = new B(0);
                        Intrinsics.checkNotNullParameter(text, "text");
                        Intrinsics.checkNotNullParameter(context, "context");
                        com.quizlet.qutils.string.g gVar = kVar.b;
                        String title = gVar != null ? gVar.a(context) : null;
                        if (title != null) {
                            Intrinsics.checkNotNullParameter(title, "title");
                            str = title;
                        } else {
                            str = null;
                        }
                        String str2 = QAlertDialogFragment.t;
                        com.quizlet.uicommon.ui.common.dialogs.h.a(new com.quizlet.uicommon.ui.common.dialogs.i(new QAlertDialogFragment.DialogData(message, str, text, null, true, null), b, null, null)).O(context.getSupportFragmentManager(), QAlertDialogFragment.t);
                        break;
                    case 1:
                        context.I(((Boolean) obj).booleanValue());
                        break;
                    default:
                        com.quizlet.login.oldlogin.c cVar = (com.quizlet.login.oldlogin.c) obj;
                        if (!(cVar instanceof LaunchBirthdayFragment)) {
                            if (!(cVar instanceof com.quizlet.login.oldlogin.d)) {
                                if (!(cVar instanceof com.quizlet.login.oldlogin.f)) {
                                    if (!(cVar instanceof com.quizlet.login.oldlogin.a)) {
                                        if (!(cVar instanceof LaunchParentEmailFragment)) {
                                            if (cVar instanceof com.quizlet.login.oldlogin.e) {
                                                context.l.getClass();
                                                Intrinsics.checkNotNullParameter(context, "activity");
                                                String str3 = MagicLinkConfirmationActivity.r;
                                                Intrinsics.checkNotNullParameter(context, "context");
                                                context.startActivity(new Intent(context, (Class<?>) MagicLinkConfirmationActivity.class));
                                                context.finish();
                                                break;
                                            }
                                        } else {
                                            LaunchParentEmailFragment launchParentEmailFragment = (LaunchParentEmailFragment) cVar;
                                            String str4 = ParentEmailFragment.n;
                                            HashMap pendingRequest = launchParentEmailFragment.a;
                                            Intrinsics.checkNotNullParameter(pendingRequest, "pendingRequest");
                                            String authProvider = launchParentEmailFragment.b;
                                            Intrinsics.checkNotNullParameter(authProvider, "authProvider");
                                            com.quizlet.login.oldlogin.b requestType = launchParentEmailFragment.c;
                                            Intrinsics.checkNotNullParameter(requestType, "requestType");
                                            ParentEmailFragment parentEmailFragment = new ParentEmailFragment();
                                            parentEmailFragment.setArguments(AbstractC3206m6.a(new Pair("pendingRequest", new HashMap(pendingRequest)), new Pair("authProvider", authProvider), new Pair("isSignUp", Boolean.TRUE), new Pair("requestType", requestType)));
                                            AbstractC1136h0 supportFragmentManager = context.getSupportFragmentManager();
                                            supportFragmentManager.getClass();
                                            C1121a c1121a = new C1121a(supportFragmentManager);
                                            c1121a.l(R.id.fragment_container, parentEmailFragment, null);
                                            c1121a.h(true, true);
                                            ((C4598b) context.k).e.setVisibility(8);
                                            context.I(false);
                                            break;
                                        }
                                    } else {
                                        ScreenState existingAccountInfo = ((com.quizlet.login.oldlogin.a) cVar).a;
                                        String str5 = AccountRecoveryModalFragment.I;
                                        Intrinsics.checkNotNullParameter(existingAccountInfo, "existingAccountInfo");
                                        AccountRecoveryModalFragment accountRecoveryModalFragment = new AccountRecoveryModalFragment();
                                        Bundle bundle2 = new Bundle();
                                        bundle2.putParcelable("existing_account_info_arg", existingAccountInfo);
                                        accountRecoveryModalFragment.setArguments(bundle2);
                                        accountRecoveryModalFragment.O(context.getSupportFragmentManager(), AccountRecoveryModalFragment.I);
                                        break;
                                    }
                                } else {
                                    boolean z = ((com.quizlet.login.oldlogin.f) cVar).a;
                                    context.l.getClass();
                                    Intrinsics.checkNotNullParameter(context, "activity");
                                    String str6 = UpgradeActivity.v;
                                    Intent intentI = AbstractC3242q6.i(context, OldSignupActivity.r, com.quizlet.features.infra.models.upgrade.a.f);
                                    intentI.setAction(z ? "require_email_confirmation" : context.getIntent().getAction());
                                    context.startActivity(intentI);
                                    context.finish();
                                    break;
                                }
                            } else {
                                boolean z2 = ((com.quizlet.login.oldlogin.d) cVar).a;
                                C4636c c4636c = context.l;
                                c4636c.getClass();
                                Intrinsics.checkNotNullParameter(context, "activity");
                                if (z2) {
                                    context.getIntent().setAction("require_email_confirmation");
                                }
                                ((com.quizlet.quizletandroid.util.g) c4636c.b).getClass();
                                com.quizlet.quizletandroid.util.g.a(context, null);
                                break;
                            }
                        } else {
                            LaunchBirthdayFragment launchBirthdayFragment = (LaunchBirthdayFragment) cVar;
                            String oauthToken = launchBirthdayFragment.a;
                            String str7 = UserBirthdayFragment.w;
                            Intrinsics.checkNotNullParameter(oauthToken, "oauthToken");
                            String authProvider2 = launchBirthdayFragment.b;
                            Intrinsics.checkNotNullParameter(authProvider2, "authProvider");
                            UserBirthdayFragment userBirthdayFragment = new UserBirthdayFragment();
                            Bundle bundle3 = new Bundle();
                            bundle3.putString("oauthToken", oauthToken);
                            bundle3.putString("authProvider", authProvider2);
                            bundle3.putBoolean("isSignUp", true);
                            userBirthdayFragment.setArguments(bundle3);
                            AbstractC1136h0 supportFragmentManager2 = context.getSupportFragmentManager();
                            supportFragmentManager2.getClass();
                            C1121a c1121a2 = new C1121a(supportFragmentManager2);
                            c1121a2.l(R.id.fragment_container, userBirthdayFragment, null);
                            c1121a2.h(true, true);
                            context.I(false);
                            break;
                        }
                        break;
                }
            }
        });
        if (getSupportFragmentManager().D(R.id.fragment_container) == null) {
            AbstractC1136h0 supportFragmentManager = getSupportFragmentManager();
            C1121a c1121aB = androidx.compose.ui.node.B.b(supportFragmentManager, supportFragmentManager);
            c1121aB.i(R.id.fragment_container, new OldNativeSignupFragment(), null, 1);
            c1121aB.g();
        }
        ((C4598b) this.k).b.setOnClickListener(new com.quizlet.quizletandroid.ui.common.adapter.viewholder.h(this, 10));
        traceA.stop();
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        return O().d();
    }

    @Override // androidx.activity.s, androidx.lifecycle.InterfaceC1261w
    public final y0 getDefaultViewModelProviderFactory() {
        ComponentCallbacks2 componentCallbacks2B = N6.b(getApplicationContext());
        return (!(componentCallbacks2B instanceof dagger.hilt.internal.b) || ((componentCallbacks2B instanceof dagger.hilt.android.internal.migration.a) && !((dagger.hilt.android.internal.migration.a) componentCallbacks2B).u())) ? super.getDefaultViewModelProviderFactory() : P6.a(this, super.getDefaultViewModelProviderFactory());
    }

    @Override // com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        P(bundle);
        if (getApplication() instanceof dagger.hilt.internal.b) {
            com.quizlet.login.authentication.login.a aVarB = O().b();
            this.n = aVarB;
            if (aVarB.l()) {
                this.n.b = getDefaultViewModelCreationExtras();
            }
        }
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        super.onDestroy();
        com.quizlet.login.authentication.login.a aVar = this.n;
        if (aVar != null) {
            aVar.b = null;
        }
    }

    @Override // dagger.hilt.android.internal.migration.a
    public final boolean u() {
        return this.q;
    }
}
