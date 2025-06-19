package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.MutableContextWrapper;

/* renamed from: com.google.android.gms.internal.ads.Fe, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1693Fe extends MutableContextWrapper {
    public Activity a;
    public Context b;
    public Context c;

    public C1693Fe(Context context) {
        super(context);
        setBaseContext(context);
    }

    public final void a(Intent intent) {
        if (this.a == null) {
            intent.setFlags(268435456);
            this.b.startActivity(intent);
            return;
        }
        com.google.android.gms.ads.internal.util.A.l("Starting activity for result with intent: " + String.valueOf(intent.getData()) + " and requestCode: 236");
        this.a.startActivityForResult(intent, 236);
    }

    @Override // android.content.ContextWrapper, android.content.Context
    public final Object getSystemService(String str) {
        return this.c.getSystemService(str);
    }

    @Override // android.content.MutableContextWrapper
    public final void setBaseContext(Context context) {
        Context applicationContext = context.getApplicationContext();
        this.b = applicationContext;
        this.a = context instanceof Activity ? (Activity) context : null;
        this.c = context;
        super.setBaseContext(applicationContext);
    }

    @Override // android.content.ContextWrapper, android.content.Context
    public final void startActivity(Intent intent) {
        Activity activity = this.a;
        if (activity != null) {
            activity.startActivity(intent);
        } else {
            intent.setFlags(268435456);
            this.b.startActivity(intent);
        }
    }
}
