package com.facebook.login;

import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.activity.result.ActivityResult;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.I;
import com.facebook.AccessToken;
import com.facebook.FacebookException;
import com.facebook.login.LoginClient;
import com.quizlet.quizletandroid.R;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Date;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public class u extends Fragment {
    public String a;
    public LoginClient.Request b;
    public LoginClient c;
    public androidx.activity.result.b d;
    public View e;

    public final LoginClient G() {
        LoginClient loginClient = this.c;
        if (loginClient != null) {
            return loginClient;
        }
        Intrinsics.m("loginClient");
        throw null;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onActivityResult(int i, int i2, Intent intent) {
        super.onActivityResult(i, i2, intent);
        G().j(i, i2, intent);
    }

    @Override // androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        Bundle bundleExtra;
        super.onCreate(bundle);
        LoginClient loginClient = bundle != null ? (LoginClient) bundle.getParcelable("loginClient") : null;
        if (loginClient == null) {
            Intrinsics.checkNotNullParameter(this, "fragment");
            loginClient = new LoginClient();
            loginClient.b = -1;
            if (loginClient.c != null) {
                throw new FacebookException("Can't set fragment once it is already set.");
            }
            loginClient.c = this;
        } else {
            if (loginClient.c != null) {
                throw new FacebookException("Can't set fragment once it is already set.");
            }
            loginClient.c = this;
        }
        this.c = loginClient;
        G().d = new s(this);
        I activity = getActivity();
        if (activity == null) {
            return;
        }
        ComponentName callingActivity = activity.getCallingActivity();
        if (callingActivity != null) {
            this.a = callingActivity.getPackageName();
        }
        Intent intent = activity.getIntent();
        if (intent != null && (bundleExtra = intent.getBundleExtra("com.facebook.LoginFragment:Request")) != null) {
            this.b = (LoginClient.Request) bundleExtra.getParcelable("request");
        }
        androidx.activity.result.contract.b bVar = new androidx.activity.result.contract.b(4);
        final androidx.compose.ui.viewinterop.b bVar2 = new androidx.compose.ui.viewinterop.b(9, this, activity);
        androidx.activity.result.b bVarRegisterForActivityResult = registerForActivityResult(bVar, new androidx.activity.result.a() { // from class: com.facebook.login.t
            @Override // androidx.activity.result.a
            public final void a(Object obj) throws IllegalAccessException, IllegalArgumentException, UnsupportedEncodingException {
                androidx.compose.ui.viewinterop.b tmp0 = bVar2;
                Intrinsics.checkNotNullParameter(tmp0, "$tmp0");
                tmp0.invoke((ActivityResult) obj);
            }
        });
        Intrinsics.checkNotNullExpressionValue(bVarRegisterForActivityResult, "registerForActivityResul…andlerCallback(activity))");
        this.d = bVarRegisterForActivityResult;
    }

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.com_facebook_login_fragment, viewGroup, false);
        View viewFindViewById = viewInflate.findViewById(R.id.com_facebook_login_fragment_progress_bar);
        Intrinsics.checkNotNullExpressionValue(viewFindViewById, "view.findViewById<View>(…in_fragment_progress_bar)");
        this.e = viewFindViewById;
        G().e = new androidx.webkit.internal.p(this, 14);
        return viewInflate;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onDestroy() {
        LoginMethodHandler loginMethodHandlerG = G().g();
        if (loginMethodHandlerG != null) {
            loginMethodHandlerG.b();
        }
        super.onDestroy();
    }

    @Override // androidx.fragment.app.Fragment
    public final void onPause() {
        super.onPause();
        View view = getView();
        View viewFindViewById = view != null ? view.findViewById(R.id.com_facebook_login_fragment_progress_bar) : null;
        if (viewFindViewById != null) {
            viewFindViewById.setVisibility(8);
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final void onResume() {
        super.onResume();
        if (this.a == null) {
            Log.e("LoginFragment", "Cannot call LoginFragment with a null calling package. This can occur if the launchMode of the caller is singleInstance.");
            I activity = getActivity();
            if (activity != null) {
                activity.finish();
                return;
            }
            return;
        }
        LoginClient loginClientG = G();
        LoginClient.Request request = this.b;
        LoginClient.Request request2 = loginClientG.g;
        if ((request2 == null || loginClientG.b < 0) && request != null) {
            if (request2 != null) {
                throw new FacebookException("Attempted to authorize while a request is pending.");
            }
            Date date = AccessToken.l;
            if (!com.google.android.gms.internal.mlkit_vision_common.D.d() || loginClientG.b()) {
                loginClientG.g = request;
                Intrinsics.checkNotNullParameter(request, "request");
                ArrayList arrayList = new ArrayList();
                D d = D.INSTAGRAM;
                D d2 = request.l;
                boolean z = d2 == d;
                o oVar = request.a;
                if (!z) {
                    if (oVar.a) {
                        arrayList.add(new GetTokenLoginMethodHandler(loginClientG));
                    }
                    if (!com.facebook.o.n && oVar.b) {
                        arrayList.add(new KatanaProxyLoginMethodHandler(loginClientG));
                    }
                } else if (!com.facebook.o.n && oVar.f) {
                    arrayList.add(new InstagramAppLoginMethodHandler(loginClientG));
                }
                if (oVar.e) {
                    arrayList.add(new CustomTabLoginMethodHandler(loginClientG));
                }
                if (oVar.c) {
                    arrayList.add(new WebViewLoginMethodHandler(loginClientG));
                }
                if (d2 != d && oVar.d) {
                    arrayList.add(new DeviceAuthMethodHandler(loginClientG));
                }
                loginClientG.a = (LoginMethodHandler[]) arrayList.toArray(new LoginMethodHandler[0]);
                loginClientG.l();
            }
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final void onSaveInstanceState(Bundle outState) {
        Intrinsics.checkNotNullParameter(outState, "outState");
        outState.putParcelable("loginClient", G());
    }
}
