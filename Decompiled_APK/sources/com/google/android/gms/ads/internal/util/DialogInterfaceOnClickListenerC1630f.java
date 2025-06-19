package com.google.android.gms.ads.internal.util;

import android.content.Context;
import android.content.DialogInterface;
import android.net.Uri;
import java.util.concurrent.atomic.AtomicInteger;

/* renamed from: com.google.android.gms.ads.internal.util.f, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class DialogInterfaceOnClickListenerC1630f implements DialogInterface.OnClickListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ DialogInterfaceOnClickListenerC1630f(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.content.DialogInterface.OnClickListener
    public final void onClick(DialogInterface dialogInterface, int i) {
        switch (this.a) {
            case 0:
                ((AtomicInteger) this.b).set(i);
                break;
            case 1:
                ((C1633i) this.b).b();
                break;
            default:
                F f = com.google.android.gms.ads.internal.j.C.c;
                F.r((Context) this.b, Uri.parse("https://support.google.com/dfp_premium/answer/7160685#push"));
                break;
        }
    }
}
