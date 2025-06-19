package com.google.android.gms.common.internal;

import android.content.Intent;
import com.google.android.gms.common.api.internal.InterfaceC1649g;

/* loaded from: classes2.dex */
public final class n extends o {
    public final /* synthetic */ Intent a;
    public final /* synthetic */ InterfaceC1649g b;

    public n(Intent intent, InterfaceC1649g interfaceC1649g) {
        this.a = intent;
        this.b = interfaceC1649g;
    }

    @Override // com.google.android.gms.common.internal.o
    public final void a() {
        Intent intent = this.a;
        if (intent != null) {
            this.b.startActivityForResult(intent, 2);
        }
    }
}
