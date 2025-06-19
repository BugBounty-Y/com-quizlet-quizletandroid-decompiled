package androidx.activity;

import android.content.Intent;
import android.content.IntentSender;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import androidx.activity.result.IntentSenderRequest;
import androidx.core.app.AbstractC1016c;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.activity.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0044p extends androidx.activity.result.h {
    public final /* synthetic */ s h;

    public C0044p(s sVar) {
        this.h = sVar;
    }

    @Override // androidx.activity.result.h
    public final void b(int i, androidx.activity.result.contract.a contract, Object obj) {
        Bundle bundleExtra;
        int i2;
        Intrinsics.checkNotNullParameter(contract, "contract");
        s sVar = this.h;
        androidx.webkit.internal.p pVarB = contract.b(sVar, obj);
        if (pVarB != null) {
            new Handler(Looper.getMainLooper()).post(new RunnableC0043o(this, i, pVarB, 0));
            return;
        }
        Intent intentA = contract.a(sVar, obj);
        if (intentA.getExtras() != null) {
            Bundle extras = intentA.getExtras();
            Intrinsics.d(extras);
            if (extras.getClassLoader() == null) {
                intentA.setExtrasClassLoader(sVar.getClassLoader());
            }
        }
        if (intentA.hasExtra("androidx.activity.result.contract.extra.ACTIVITY_OPTIONS_BUNDLE")) {
            bundleExtra = intentA.getBundleExtra("androidx.activity.result.contract.extra.ACTIVITY_OPTIONS_BUNDLE");
            intentA.removeExtra("androidx.activity.result.contract.extra.ACTIVITY_OPTIONS_BUNDLE");
        } else {
            bundleExtra = null;
        }
        Bundle bundle = bundleExtra;
        if ("androidx.activity.result.contract.action.REQUEST_PERMISSIONS".equals(intentA.getAction())) {
            String[] stringArrayExtra = intentA.getStringArrayExtra("androidx.activity.result.contract.extra.PERMISSIONS");
            if (stringArrayExtra == null) {
                stringArrayExtra = new String[0];
            }
            AbstractC1016c.g(sVar, stringArrayExtra, i);
            return;
        }
        if (!"androidx.activity.result.contract.action.INTENT_SENDER_REQUEST".equals(intentA.getAction())) {
            sVar.startActivityForResult(intentA, i, bundle);
            return;
        }
        IntentSenderRequest intentSenderRequest = (IntentSenderRequest) intentA.getParcelableExtra("androidx.activity.result.contract.extra.INTENT_SENDER_REQUEST");
        try {
            Intrinsics.d(intentSenderRequest);
            i2 = i;
        } catch (IntentSender.SendIntentException e) {
            e = e;
            i2 = i;
        }
        try {
            sVar.startIntentSenderForResult(intentSenderRequest.a, i2, intentSenderRequest.b, intentSenderRequest.c, intentSenderRequest.d, 0, bundle);
        } catch (IntentSender.SendIntentException e2) {
            e = e2;
            new Handler(Looper.getMainLooper()).post(new RunnableC0043o(this, i2, e, 1));
        }
    }
}
