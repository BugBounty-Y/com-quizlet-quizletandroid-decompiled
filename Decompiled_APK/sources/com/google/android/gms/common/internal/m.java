package com.google.android.gms.common.internal;

import android.app.Activity;
import android.content.Intent;

/* loaded from: classes2.dex */
public final class m extends o {
    public final /* synthetic */ Intent a;
    public final /* synthetic */ Activity b;
    public final /* synthetic */ int c;

    public m(Activity activity, Intent intent, int i) {
        this.a = intent;
        this.b = activity;
        this.c = i;
    }

    @Override // com.google.android.gms.common.internal.o
    public final void a() {
        Intent intent = this.a;
        if (intent != null) {
            this.b.startActivityForResult(intent, this.c);
        }
    }
}
