package com.facebook;

import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.os.Bundle;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.I;
import com.facebook.internal.C;
import com.facebook.internal.C1556k;
import com.quizlet.quizletandroid.R;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public class FacebookActivity extends I {
    public Fragment b;

    @Override // androidx.fragment.app.I, android.app.Activity
    public final void dump(String prefix, FileDescriptor fileDescriptor, PrintWriter writer, String[] strArr) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(prefix, "prefix");
            Intrinsics.checkNotNullParameter(writer, "writer");
            super.dump(prefix, fileDescriptor, writer, strArr);
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    @Override // androidx.activity.s, android.app.Activity, android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration newConfig) {
        Intrinsics.checkNotNullParameter(newConfig, "newConfig");
        super.onConfigurationChanged(newConfig);
        Fragment fragment = this.b;
        if (fragment != null) {
            fragment.onConfigurationChanged(newConfig);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r5v9, types: [androidx.fragment.app.Fragment, androidx.fragment.app.t, com.facebook.internal.k] */
    @Override // androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        com.facebook.login.u uVar;
        FacebookException facebookException;
        super.onCreate(bundle);
        Intent intent = getIntent();
        if (!o.o.get()) {
            Context applicationContext = getApplicationContext();
            Intrinsics.checkNotNullExpressionValue(applicationContext, "applicationContext");
            synchronized (o.class) {
                Intrinsics.checkNotNullParameter(applicationContext, "applicationContext");
                o.k(applicationContext, null);
            }
        }
        setContentView(R.layout.com_facebook_activity_layout);
        if (!"PassThrough".equals(intent.getAction())) {
            Intent intent2 = getIntent();
            AbstractC1136h0 supportFragmentManager = getSupportFragmentManager();
            Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
            Fragment fragmentE = supportFragmentManager.E("SingleFragment");
            if (fragmentE == null) {
                if ("FacebookDialogFragment".equals(intent2.getAction())) {
                    ?? c1556k = new C1556k();
                    c1556k.setRetainInstance(true);
                    c1556k.O(supportFragmentManager, "SingleFragment");
                    uVar = c1556k;
                } else {
                    com.facebook.login.u uVar2 = new com.facebook.login.u();
                    uVar2.setRetainInstance(true);
                    C1121a c1121a = new C1121a(supportFragmentManager);
                    c1121a.i(R.id.com_facebook_fragment_container, uVar2, "SingleFragment", 1);
                    c1121a.g();
                    uVar = uVar2;
                }
                fragmentE = uVar;
            }
            this.b = fragmentE;
            return;
        }
        Intent requestIntent = getIntent();
        Intrinsics.checkNotNullExpressionValue(requestIntent, "requestIntent");
        Bundle bundleH = C.h(requestIntent);
        if (com.facebook.internal.instrument.crashshield.a.b(C.class) || bundleH == null) {
            facebookException = null;
        } else {
            try {
                String string = bundleH.getString("error_type");
                if (string == null) {
                    string = bundleH.getString("com.facebook.platform.status.ERROR_TYPE");
                }
                String string2 = bundleH.getString("error_description");
                if (string2 == null) {
                    string2 = bundleH.getString("com.facebook.platform.status.ERROR_DESCRIPTION");
                }
                facebookException = (string == null || !string.equalsIgnoreCase("UserCanceled")) ? new FacebookException(string2) : new FacebookOperationCanceledException(string2);
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(C.class, th);
            }
        }
        Intent intent3 = getIntent();
        Intrinsics.checkNotNullExpressionValue(intent3, "intent");
        setResult(0, C.e(intent3, null, facebookException));
        finish();
    }
}
