package com.google.android.gms.ads;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.RemoteException;
import android.widget.LinearLayout;
import com.google.android.gms.ads.internal.client.C1588d;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.internal.client.InterfaceC1613p0;
import com.google.android.gms.internal.ads.BinderC2739va;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class OutOfContextTestingActivity extends Activity {
    @Override // android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        C1608n c1608n = C1614q.f.b;
        BinderC2739va binderC2739va = new BinderC2739va();
        c1608n.getClass();
        InterfaceC1613p0 interfaceC1613p0 = (InterfaceC1613p0) new C1588d(this, binderC2739va).d(this, false);
        if (interfaceC1613p0 == null) {
            finish();
            return;
        }
        setContentView(R.layout.admob_empty_layout);
        LinearLayout linearLayout = (LinearLayout) findViewById(R.id.layout);
        Intent intent = getIntent();
        if (intent == null) {
            finish();
            return;
        }
        String stringExtra = intent.getStringExtra("adUnit");
        if (stringExtra == null) {
            finish();
            return;
        }
        try {
            interfaceC1613p0.F2(stringExtra, new com.google.android.gms.dynamic.b(this), new com.google.android.gms.dynamic.b(linearLayout));
        } catch (RemoteException unused) {
            finish();
        }
    }
}
