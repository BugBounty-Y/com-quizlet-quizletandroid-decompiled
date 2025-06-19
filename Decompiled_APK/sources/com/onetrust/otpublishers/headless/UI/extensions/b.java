package com.onetrust.otpublishers.headless.UI.extensions;

import android.os.Handler;
import android.os.Looper;
import android.widget.ImageView;
import com.bumptech.glide.request.e;
import com.facebook.login.E;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b implements e {
    public final /* synthetic */ String a;
    public final /* synthetic */ String b;
    public final /* synthetic */ String c;
    public final /* synthetic */ ImageView d;
    public final /* synthetic */ int e;

    public b(int i, ImageView imageView, String str, String str2, String str3) {
        this.a = str;
        this.b = str2;
        this.c = str3;
        this.d = imageView;
        this.e = i;
    }

    @Override // com.bumptech.glide.request.e
    public final void a(Object obj) {
        OTLogger.c("OneTrust", 3, "Logo shown for " + this.a + " for url " + this.b);
    }

    @Override // com.bumptech.glide.request.e
    public final void b() {
        StringBuilder sb = new StringBuilder("Logo shown for ");
        String str = this.a;
        sb.append(str);
        sb.append(" failed for url ");
        String str2 = this.b;
        sb.append(str2);
        OTLogger.c("OneTrust", 3, sb.toString());
        String str3 = this.c;
        if (Intrinsics.b(str2, str3)) {
            return;
        }
        new Handler(Looper.getMainLooper()).post(new E(this.d, str3, this.e, str));
    }
}
