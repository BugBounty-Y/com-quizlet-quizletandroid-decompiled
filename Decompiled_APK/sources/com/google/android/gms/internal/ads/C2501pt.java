package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.pt, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2501pt implements InterfaceC2715ut {
    public final char a;

    public C2501pt(char c) {
        this.a = c;
    }

    public final boolean a(char c) {
        return c == this.a;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2715ut
    public final /* synthetic */ boolean b(Object obj) {
        return a(((Character) obj).charValue());
    }

    public final String toString() {
        char[] cArr = new char[6];
        cArr[0] = '\\';
        cArr[1] = 'u';
        cArr[2] = 0;
        cArr[3] = 0;
        cArr[4] = 0;
        cArr[5] = 0;
        int i = this.a;
        for (int i2 = 0; i2 < 4; i2++) {
            cArr[5 - i2] = "0123456789ABCDEF".charAt(i & 15);
            i >>= 4;
        }
        return android.support.v4.media.session.a.B("CharMatcher.is('", String.copyValueOf(cArr), "')");
    }
}
