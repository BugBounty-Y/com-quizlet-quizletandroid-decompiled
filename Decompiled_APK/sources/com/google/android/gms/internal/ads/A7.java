package com.google.android.gms.internal.ads;

import android.text.TextUtils;

/* loaded from: classes2.dex */
public final class A7 implements Xh {
    public final String a;
    public final String b;

    public /* synthetic */ A7(String str, String str2) {
        this.a = str;
        this.b = str2;
    }

    public static A7 a(String str, String str2) {
        if (TextUtils.isEmpty(str)) {
            throw new IllegalArgumentException("Name is null or empty");
        }
        if (TextUtils.isEmpty(str2)) {
            throw new IllegalArgumentException("Version is null or empty");
        }
        return new A7(str, str2);
    }

    @Override // com.google.android.gms.internal.ads.Xh
    /* renamed from: b */
    public void mo16b(Object obj) {
        ((com.google.android.gms.ads.admanager.a) obj).onAppEvent(this.a, this.b);
    }
}
