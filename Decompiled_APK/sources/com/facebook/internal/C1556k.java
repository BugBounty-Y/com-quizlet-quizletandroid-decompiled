package com.facebook.internal;

import android.app.Dialog;
import android.content.Intent;
import android.content.res.Configuration;
import android.os.Bundle;
import androidx.compose.animation.d0;
import androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t;
import com.amazon.device.ads.DTBMetricsConfiguration;
import com.facebook.AccessToken;
import com.facebook.FacebookException;
import java.util.Date;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* renamed from: com.facebook.internal.k, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1556k extends DialogInterfaceOnCancelListenerC1151t {
    public Dialog q;

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        Dialog dialog = this.q;
        if (dialog != null) {
            return dialog;
        }
        androidx.fragment.app.I activity = getActivity();
        if (activity != null) {
            Intent intent = activity.getIntent();
            Intrinsics.checkNotNullExpressionValue(intent, "fragmentActivity.intent");
            activity.setResult(-1, C.e(intent, null, null));
            activity.finish();
        }
        this.h = false;
        Dialog dialogK = super.K(bundle);
        Intrinsics.checkNotNullExpressionValue(dialogK, "super.onCreateDialog(savedInstanceState)");
        return dialogK;
    }

    @Override // androidx.fragment.app.Fragment, android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration newConfig) {
        Intrinsics.checkNotNullParameter(newConfig, "newConfig");
        super.onConfigurationChanged(newConfig);
        if ((this.q instanceof S) && isResumed()) {
            Dialog dialog = this.q;
            Intrinsics.e(dialog, "null cannot be cast to non-null type com.facebook.internal.WebDialog");
            ((S) dialog).d();
        }
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        androidx.fragment.app.I context;
        String url;
        S s;
        final int i = 1;
        final int i2 = 0;
        super.onCreate(bundle);
        if (this.q == null && (context = getActivity()) != null) {
            Intent intent = context.getIntent();
            Intrinsics.checkNotNullExpressionValue(intent, "intent");
            Bundle bundleH = C.h(intent);
            if (bundleH != null ? bundleH.getBoolean("is_fallback", false) : false) {
                url = bundleH != null ? bundleH.getString(DTBMetricsConfiguration.APSMETRICS_URL) : null;
                if (J.D(url)) {
                    com.facebook.o oVar = com.facebook.o.a;
                    context.finish();
                    return;
                }
                String expectedRedirectUrl = d0.s(new Object[]{com.facebook.o.b()}, 1, "fb%s://bridge/", "format(format, *args)");
                int i3 = DialogC1560o.o;
                Intrinsics.e(url, "null cannot be cast to non-null type kotlin.String");
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(url, "url");
                Intrinsics.checkNotNullParameter(expectedRedirectUrl, "expectedRedirectUrl");
                S.b(context);
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(url, "url");
                AbstractC1554i.k();
                int i4 = S.m;
                if (i4 == 0) {
                    AbstractC1554i.k();
                    i4 = S.m;
                }
                DialogC1560o dialogC1560o = new DialogC1560o(context, i4);
                dialogC1560o.b = "fbconnect://success";
                dialogC1560o.a = url;
                Intrinsics.checkNotNullParameter(expectedRedirectUrl, "expectedRedirectUrl");
                dialogC1560o.b = expectedRedirectUrl;
                dialogC1560o.c = new M(this) { // from class: com.facebook.internal.j
                    public final /* synthetic */ C1556k b;

                    {
                        this.b = this;
                    }

                    @Override // com.facebook.internal.M
                    public final void a(Bundle bundle2, FacebookException facebookException) {
                        switch (i) {
                            case 0:
                                C1556k this$0 = this.b;
                                Intrinsics.checkNotNullParameter(this$0, "this$0");
                                androidx.fragment.app.I activity = this$0.getActivity();
                                if (activity != null) {
                                    Intent intent2 = activity.getIntent();
                                    Intrinsics.checkNotNullExpressionValue(intent2, "fragmentActivity.intent");
                                    activity.setResult(facebookException == null ? -1 : 0, C.e(intent2, bundle2, facebookException));
                                    activity.finish();
                                    break;
                                }
                                break;
                            default:
                                C1556k this$02 = this.b;
                                Intrinsics.checkNotNullParameter(this$02, "this$0");
                                androidx.fragment.app.I activity2 = this$02.getActivity();
                                if (activity2 != null) {
                                    Intent intent3 = new Intent();
                                    if (bundle2 == null) {
                                        bundle2 = new Bundle();
                                    }
                                    intent3.putExtras(bundle2);
                                    activity2.setResult(-1, intent3);
                                    activity2.finish();
                                    break;
                                }
                                break;
                        }
                    }
                };
                s = dialogC1560o;
            } else {
                String action = bundleH != null ? bundleH.getString("action") : null;
                Bundle bundle2 = bundleH != null ? bundleH.getBundle("params") : null;
                if (J.D(action)) {
                    com.facebook.o oVar2 = com.facebook.o.a;
                    context.finish();
                    return;
                }
                Intrinsics.e(action, "null cannot be cast to non-null type kotlin.String");
                Intrinsics.checkNotNullParameter(context, "context");
                Intrinsics.checkNotNullParameter(action, "action");
                Date date = AccessToken.l;
                AccessToken accessTokenC = com.google.android.gms.internal.mlkit_vision_common.D.c();
                url = com.google.android.gms.internal.mlkit_vision_common.D.d() ? null : J.t(context);
                if (bundle2 == null) {
                    bundle2 = new Bundle();
                }
                M m = new M(this) { // from class: com.facebook.internal.j
                    public final /* synthetic */ C1556k b;

                    {
                        this.b = this;
                    }

                    @Override // com.facebook.internal.M
                    public final void a(Bundle bundle22, FacebookException facebookException) {
                        switch (i2) {
                            case 0:
                                C1556k this$0 = this.b;
                                Intrinsics.checkNotNullParameter(this$0, "this$0");
                                androidx.fragment.app.I activity = this$0.getActivity();
                                if (activity != null) {
                                    Intent intent2 = activity.getIntent();
                                    Intrinsics.checkNotNullExpressionValue(intent2, "fragmentActivity.intent");
                                    activity.setResult(facebookException == null ? -1 : 0, C.e(intent2, bundle22, facebookException));
                                    activity.finish();
                                    break;
                                }
                                break;
                            default:
                                C1556k this$02 = this.b;
                                Intrinsics.checkNotNullParameter(this$02, "this$0");
                                androidx.fragment.app.I activity2 = this$02.getActivity();
                                if (activity2 != null) {
                                    Intent intent3 = new Intent();
                                    if (bundle22 == null) {
                                        bundle22 = new Bundle();
                                    }
                                    intent3.putExtras(bundle22);
                                    activity2.setResult(-1, intent3);
                                    activity2.finish();
                                    break;
                                }
                                break;
                        }
                    }
                };
                if (accessTokenC != null) {
                    bundle2.putString("app_id", accessTokenC.h);
                    bundle2.putString("access_token", accessTokenC.e);
                } else {
                    bundle2.putString("app_id", url);
                }
                int i5 = S.m;
                Intrinsics.checkNotNullParameter(context, "context");
                S.b(context);
                s = new S(context, action, bundle2, com.facebook.login.D.FACEBOOK, m);
            }
            this.q = s;
        }
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        Dialog dialog = this.l;
        if (dialog != null && getRetainInstance()) {
            dialog.setDismissMessage(null);
        }
        super.onDestroyView();
    }

    @Override // androidx.fragment.app.Fragment
    public final void onResume() {
        super.onResume();
        Dialog dialog = this.q;
        if (dialog instanceof S) {
            Intrinsics.e(dialog, "null cannot be cast to non-null type com.facebook.internal.WebDialog");
            ((S) dialog).d();
        }
    }
}
