package com.google.android.gms.internal.ads;

import android.content.ContentResolver;
import android.content.Context;
import android.database.ContentObserver;
import android.net.Uri;
import android.os.Handler;

/* renamed from: com.google.android.gms.internal.ads.gE, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2092gE extends ContentObserver {
    public final ContentResolver a;
    public final Uri b;
    public final /* synthetic */ Tm c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C2092gE(Tm tm, Handler handler, ContentResolver contentResolver, Uri uri) {
        super(handler);
        this.c = tm;
        this.a = contentResolver;
        this.b = uri;
    }

    @Override // android.database.ContentObserver
    public final void onChange(boolean z) {
        Tm tm = this.c;
        tm.b(C2004eE.b((Context) tm.b, (Wl) tm.i, (C2883yp) tm.h));
    }
}
