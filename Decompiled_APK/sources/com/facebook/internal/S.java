package com.facebook.internal;

import android.app.Activity;
import android.app.Dialog;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.DisplayMetrics;
import android.view.Display;
import android.view.KeyEvent;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.view.autofill.AutofillManager;
import android.webkit.WebSettings;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import com.amazon.device.ads.DtbConstants;
import com.facebook.FacebookException;
import com.facebook.FacebookOperationCanceledException;
import com.quizlet.quizletandroid.R;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public class S extends Dialog {
    public static volatile int m;
    public String a;
    public String b;
    public M c;
    public Q d;
    public ProgressDialog e;
    public ImageView f;
    public FrameLayout g;
    public final O h;
    public boolean i;
    public boolean j;
    public boolean k;
    public WindowManager.LayoutParams l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public S(androidx.fragment.app.I i, String str, Bundle bundle, com.facebook.login.D d, M m2) {
        Uri uriA;
        super(i, m);
        AbstractC1554i.k();
        this.b = "fbconnect://success";
        bundle = bundle == null ? new Bundle() : bundle;
        String str2 = J.A(i) ? "fbconnect://chrome_os_success" : "fbconnect://success";
        this.b = str2;
        bundle.putString("redirect_uri", str2);
        bundle.putString("display", "touch");
        bundle.putString("client_id", com.facebook.o.b());
        String str3 = String.format(Locale.ROOT, "android-%s", Arrays.copyOf(new Object[]{"18.0.3"}, 1));
        Intrinsics.checkNotNullExpressionValue(str3, "format(locale, format, *args)");
        bundle.putString("sdk", str3);
        this.c = m2;
        if (Intrinsics.b(str, "share") && bundle.containsKey("media")) {
            this.h = new O(this, str, bundle);
            return;
        }
        if (P.a[d.ordinal()] == 1) {
            uriA = J.a(J.r(), "oauth/authorize", bundle);
        } else {
            uriA = J.a(J.p(), com.facebook.o.d() + "/dialog/" + str, bundle);
        }
        this.a = uriA.toString();
    }

    public static int a(float f, int i, int i2, int i3) {
        int i4 = (int) (i / f);
        return (int) (i * (i4 <= i2 ? 1.0d : i4 >= i3 ? 0.5d : (((i3 - i4) / (i3 - i2)) * 0.5d) + 0.5d));
    }

    public static final void b(androidx.fragment.app.I i) {
        if (i == null) {
            return;
        }
        try {
            ApplicationInfo applicationInfo = i.getPackageManager().getApplicationInfo(i.getPackageName(), 128);
            if ((applicationInfo != null ? applicationInfo.metaData : null) != null && m == 0) {
                int i2 = applicationInfo.metaData.getInt("com.facebook.sdk.WebDialogTheme");
                if (i2 == 0) {
                    i2 = R.style.com_facebook_activity_theme;
                }
                m = i2;
            }
        } catch (PackageManager.NameNotFoundException unused) {
        }
    }

    public Bundle c(String str) {
        Uri uri = Uri.parse(str);
        Bundle bundleI = J.I(uri.getQuery());
        bundleI.putAll(J.I(uri.getFragment()));
        return bundleI;
    }

    @Override // android.app.Dialog, android.content.DialogInterface
    public void cancel() {
        if (this.c == null || this.i) {
            return;
        }
        e(new FacebookOperationCanceledException());
    }

    public final void d() {
        Object systemService = getContext().getSystemService("window");
        Intrinsics.e(systemService, "null cannot be cast to non-null type android.view.WindowManager");
        Display defaultDisplay = ((WindowManager) systemService).getDefaultDisplay();
        DisplayMetrics displayMetrics = new DisplayMetrics();
        defaultDisplay.getMetrics(displayMetrics);
        int i = displayMetrics.widthPixels;
        int i2 = displayMetrics.heightPixels;
        int i3 = i < i2 ? i : i2;
        if (i < i2) {
            i = i2;
        }
        int iMin = Math.min(a(displayMetrics.density, i3, DtbConstants.DEFAULT_PLAYER_HEIGHT, 800), displayMetrics.widthPixels);
        int iMin2 = Math.min(a(displayMetrics.density, i, 800, 1280), displayMetrics.heightPixels);
        Window window = getWindow();
        if (window != null) {
            window.setLayout(iMin, iMin2);
        }
    }

    @Override // android.app.Dialog, android.content.DialogInterface
    public final void dismiss() {
        ProgressDialog progressDialog;
        Q q = this.d;
        if (q != null) {
            q.stopLoading();
        }
        if (!this.j && (progressDialog = this.e) != null && progressDialog.isShowing()) {
            progressDialog.dismiss();
        }
        super.dismiss();
    }

    public final void e(Exception exc) {
        if (this.c == null || this.i) {
            return;
        }
        this.i = true;
        FacebookException facebookException = exc instanceof FacebookException ? (FacebookException) exc : new FacebookException(exc);
        M m2 = this.c;
        if (m2 != null) {
            m2.a(null, facebookException);
        }
        dismiss();
    }

    public final void f(int i) {
        LinearLayout linearLayout = new LinearLayout(getContext());
        Q q = new Q(getContext());
        this.d = q;
        q.setVerticalScrollBarEnabled(false);
        Q q2 = this.d;
        if (q2 != null) {
            q2.setHorizontalScrollBarEnabled(false);
        }
        Q q3 = this.d;
        if (q3 != null) {
            q3.setWebViewClient(new L(this, 0));
        }
        Q q4 = this.d;
        WebSettings settings = q4 != null ? q4.getSettings() : null;
        if (settings != null) {
            settings.setJavaScriptEnabled(true);
        }
        Q q5 = this.d;
        if (q5 != null) {
            String str = this.a;
            if (str == null) {
                throw new IllegalStateException("Required value was null.");
            }
            q5.loadUrl(str);
        }
        Q q6 = this.d;
        if (q6 != null) {
            q6.setLayoutParams(new FrameLayout.LayoutParams(-1, -1));
        }
        Q q7 = this.d;
        if (q7 != null) {
            q7.setVisibility(4);
        }
        Q q8 = this.d;
        WebSettings settings2 = q8 != null ? q8.getSettings() : null;
        if (settings2 != null) {
            settings2.setSavePassword(false);
        }
        Q q9 = this.d;
        WebSettings settings3 = q9 != null ? q9.getSettings() : null;
        if (settings3 != null) {
            settings3.setSaveFormData(false);
        }
        Q q10 = this.d;
        if (q10 != null) {
            q10.setFocusable(true);
        }
        Q q11 = this.d;
        if (q11 != null) {
            q11.setFocusableInTouchMode(true);
        }
        Q q12 = this.d;
        if (q12 != null) {
            q12.setOnTouchListener(new com.braze.ui.a(1));
        }
        linearLayout.setPadding(i, i, i, i);
        linearLayout.addView(this.d);
        linearLayout.setBackgroundColor(-872415232);
        FrameLayout frameLayout = this.g;
        if (frameLayout != null) {
            frameLayout.addView(linearLayout);
        }
    }

    @Override // android.app.Dialog, android.view.Window.Callback
    public final void onAttachedToWindow() {
        WindowManager.LayoutParams layoutParams;
        Window window;
        WindowManager.LayoutParams attributes;
        this.j = false;
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "context");
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(context, "context");
        AutofillManager autofillManager = (AutofillManager) context.getSystemService(AutofillManager.class);
        if (autofillManager != null && autofillManager.isAutofillSupported() && autofillManager.isEnabled() && (layoutParams = this.l) != null) {
            if ((layoutParams != null ? layoutParams.token : null) == null) {
                if (layoutParams != null) {
                    Activity ownerActivity = getOwnerActivity();
                    layoutParams.token = (ownerActivity == null || (window = ownerActivity.getWindow()) == null || (attributes = window.getAttributes()) == null) ? null : attributes.token;
                }
                WindowManager.LayoutParams layoutParams2 = this.l;
                Objects.toString(layoutParams2 != null ? layoutParams2.token : null);
                com.facebook.o oVar = com.facebook.o.a;
            }
        }
        super.onAttachedToWindow();
    }

    @Override // android.app.Dialog
    public final void onCreate(Bundle bundle) throws Resources.NotFoundException {
        super.onCreate(bundle);
        ProgressDialog progressDialog = new ProgressDialog(getContext());
        this.e = progressDialog;
        progressDialog.requestWindowFeature(1);
        ProgressDialog progressDialog2 = this.e;
        if (progressDialog2 != null) {
            progressDialog2.setMessage(getContext().getString(R.string.com_facebook_loading));
        }
        ProgressDialog progressDialog3 = this.e;
        if (progressDialog3 != null) {
            progressDialog3.setCanceledOnTouchOutside(false);
        }
        ProgressDialog progressDialog4 = this.e;
        if (progressDialog4 != null) {
            progressDialog4.setOnCancelListener(new K(this, 0));
        }
        requestWindowFeature(1);
        this.g = new FrameLayout(getContext());
        d();
        Window window = getWindow();
        if (window != null) {
            window.setGravity(17);
        }
        Window window2 = getWindow();
        if (window2 != null) {
            window2.setSoftInputMode(16);
        }
        ImageView imageView = new ImageView(getContext());
        this.f = imageView;
        imageView.setOnClickListener(new com.braze.ui.inappmessage.d(this, 3));
        Drawable drawable = getContext().getResources().getDrawable(2131230969);
        ImageView imageView2 = this.f;
        if (imageView2 != null) {
            imageView2.setImageDrawable(drawable);
        }
        ImageView imageView3 = this.f;
        if (imageView3 != null) {
            imageView3.setVisibility(4);
        }
        if (this.a != null) {
            ImageView imageView4 = this.f;
            if (imageView4 == null) {
                throw new IllegalStateException("Required value was null.");
            }
            f((imageView4.getDrawable().getIntrinsicWidth() / 2) + 1);
        }
        FrameLayout frameLayout = this.g;
        if (frameLayout != null) {
            frameLayout.addView(this.f, new ViewGroup.LayoutParams(-2, -2));
        }
        FrameLayout frameLayout2 = this.g;
        if (frameLayout2 == null) {
            throw new IllegalStateException("Required value was null.");
        }
        setContentView(frameLayout2);
    }

    @Override // android.app.Dialog, android.view.Window.Callback
    public final void onDetachedFromWindow() {
        this.j = true;
        super.onDetachedFromWindow();
    }

    @Override // android.app.Dialog, android.view.KeyEvent.Callback
    public final boolean onKeyDown(int i, KeyEvent event) {
        Intrinsics.checkNotNullParameter(event, "event");
        if (i == 4) {
            Q q = this.d;
            if (q != null && q.canGoBack()) {
                Q q2 = this.d;
                if (q2 != null) {
                    q2.goBack();
                }
                return true;
            }
            cancel();
        }
        return super.onKeyDown(i, event);
    }

    @Override // android.app.Dialog
    public final void onStart() {
        super.onStart();
        O o = this.h;
        if (o != null) {
            if ((o != null ? o.getStatus() : null) == AsyncTask.Status.PENDING) {
                if (o != null) {
                    o.execute(new Void[0]);
                }
                ProgressDialog progressDialog = this.e;
                if (progressDialog != null) {
                    progressDialog.show();
                    return;
                }
                return;
            }
        }
        d();
    }

    @Override // android.app.Dialog
    public final void onStop() {
        O o = this.h;
        if (o != null) {
            o.cancel(true);
            ProgressDialog progressDialog = this.e;
            if (progressDialog != null) {
                progressDialog.dismiss();
            }
        }
        super.onStop();
    }

    @Override // android.app.Dialog, android.view.Window.Callback
    public final void onWindowAttributesChanged(WindowManager.LayoutParams params) {
        Intrinsics.checkNotNullParameter(params, "params");
        if (params.token == null) {
            this.l = params;
        }
        super.onWindowAttributesChanged(params);
    }
}
