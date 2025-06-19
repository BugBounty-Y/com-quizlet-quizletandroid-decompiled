package com.facebook;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.Uri;
import android.os.Bundle;
import androidx.appcompat.app.L;
import com.facebook.internal.C;
import com.facebook.internal.C1549d;
import com.facebook.internal.J;
import com.facebook.login.C1566c;
import com.facebook.login.D;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class CustomTabMainActivity extends Activity {
    public static final /* synthetic */ int c = 0;
    public boolean a = true;
    public C1549d b;

    public final void a(int i, Intent intent) {
        Bundle bundle;
        C1549d c1549d = this.b;
        if (c1549d != null) {
            androidx.localbroadcastmanager.content.b.a(this).d(c1549d);
        }
        if (intent != null) {
            String stringExtra = intent.getStringExtra("CustomTabMainActivity.extra_url");
            if (stringExtra != null) {
                Uri uri = Uri.parse(stringExtra);
                bundle = J.I(uri.getQuery());
                bundle.putAll(J.I(uri.getFragment()));
            } else {
                bundle = new Bundle();
            }
            Intent intent2 = getIntent();
            Intrinsics.checkNotNullExpressionValue(intent2, "intent");
            Intent intentE = C.e(intent2, bundle, null);
            if (intentE != null) {
                intent = intentE;
            }
            setResult(i, intent);
        } else {
            Intent intent3 = getIntent();
            Intrinsics.checkNotNullExpressionValue(intent3, "intent");
            setResult(i, C.e(intent3, null, null));
        }
        finish();
    }

    @Override // android.app.Activity
    public final void onCreate(Bundle bundle) {
        String action;
        D d;
        L l;
        boolean z;
        Uri uriA;
        super.onCreate(bundle);
        if ("CustomTabActivity.action_customTabRedirect".equals(getIntent().getAction())) {
            setResult(0);
            finish();
            return;
        }
        if (bundle != null || (action = getIntent().getStringExtra("CustomTabMainActivity.extra_action")) == null) {
            return;
        }
        Bundle bundleExtra = getIntent().getBundleExtra("CustomTabMainActivity.extra_params");
        String stringExtra = getIntent().getStringExtra("CustomTabMainActivity.extra_chromePackage");
        String stringExtra2 = getIntent().getStringExtra("CustomTabMainActivity.extra_targetApp");
        D[] dArrValues = D.values();
        int length = dArrValues.length;
        int i = 0;
        while (true) {
            if (i >= length) {
                d = D.FACEBOOK;
                break;
            }
            d = dArrValues[i];
            if (d.a.equals(stringExtra2)) {
                break;
            } else {
                i++;
            }
        }
        if (k.a[d.ordinal()] == 1) {
            Intrinsics.checkNotNullParameter(action, "action");
            l = new com.facebook.internal.z(bundleExtra, action);
            if (bundleExtra == null) {
                bundleExtra = new Bundle();
            }
            Intrinsics.checkNotNullParameter(action, "action");
            if (action.equals("oauth")) {
                uriA = J.a(J.r(), "oauth/authorize", bundleExtra);
            } else {
                uriA = J.a(J.r(), o.d() + "/dialog/" + action, bundleExtra);
            }
            if (!com.facebook.internal.instrument.crashshield.a.b(l)) {
                try {
                    Intrinsics.checkNotNullParameter(uriA, "<set-?>");
                    l.b = uriA;
                } catch (Throwable th) {
                    com.facebook.internal.instrument.crashshield.a.a(l, th);
                }
            }
        } else {
            l = new L(bundleExtra, action);
        }
        if (com.facebook.internal.instrument.crashshield.a.b(l)) {
            z = false;
        } else {
            try {
                Intrinsics.checkNotNullParameter(this, "activity");
                ReentrantLock reentrantLock = C1566c.d;
                reentrantLock.lock();
                androidx.work.impl.model.n nVar = C1566c.c;
                C1566c.c = null;
                reentrantLock.unlock();
                androidx.work.impl.model.c cVarC = new androidx.browser.customtabs.k(nVar).c();
                ((Intent) cVarC.b).setPackage(stringExtra);
                try {
                    cVarC.v(this, (Uri) l.b);
                    z = true;
                } catch (ActivityNotFoundException unused) {
                }
            } catch (Throwable th2) {
                com.facebook.internal.instrument.crashshield.a.a(l, th2);
            }
        }
        this.a = false;
        if (!z) {
            setResult(0, getIntent().putExtra("CustomTabMainActivity.no_activity_exception", true));
            finish();
        } else {
            C1549d c1549d = new C1549d(this, 4);
            this.b = c1549d;
            androidx.localbroadcastmanager.content.b.a(this).b(c1549d, new IntentFilter("CustomTabActivity.action_customTabRedirect"));
        }
    }

    @Override // android.app.Activity
    public final void onNewIntent(Intent intent) {
        Intrinsics.checkNotNullParameter(intent, "intent");
        super.onNewIntent(intent);
        if ("CustomTabMainActivity.action_refresh".equals(intent.getAction())) {
            androidx.localbroadcastmanager.content.b.a(this).c(new Intent("CustomTabActivity.action_destroy"));
            a(-1, intent);
        } else if ("CustomTabActivity.action_customTabRedirect".equals(intent.getAction())) {
            a(-1, intent);
        }
    }

    @Override // android.app.Activity
    public final void onResume() {
        super.onResume();
        if (this.a) {
            a(0, null);
        }
        this.a = true;
    }
}
