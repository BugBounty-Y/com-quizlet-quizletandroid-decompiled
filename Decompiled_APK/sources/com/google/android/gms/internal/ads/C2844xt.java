package com.google.android.gms.internal.ads;

import java.util.regex.Matcher;

/* renamed from: com.google.android.gms.internal.ads.xt, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2844xt extends AbstractC2930zt {
    public final /* synthetic */ int f;
    public final /* synthetic */ Object g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C2844xt(CharSequence charSequence, Object obj, int i) {
        super(charSequence);
        this.f = i;
        this.g = obj;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2930zt
    public final int a(int i) {
        switch (this.f) {
            case 0:
                return i + 1;
            default:
                return ((Matcher) ((C2586rt) this.g).b).end();
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2930zt
    public final int b(int i) {
        switch (this.f) {
            case 0:
                CharSequence charSequence = this.c;
                int length = charSequence.length();
                AbstractC1981ds.p(i, length);
                while (i < length) {
                    if (((C2501pt) this.g).a(charSequence.charAt(i))) {
                        return i;
                    }
                    i++;
                }
                return -1;
            default:
                Matcher matcher = (Matcher) ((C2586rt) this.g).b;
                if (matcher.find(i)) {
                    return matcher.start();
                }
                return -1;
        }
    }
}
