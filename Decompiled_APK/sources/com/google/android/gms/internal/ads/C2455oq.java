package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.client.zze;
import java.util.HashSet;

/* renamed from: com.google.android.gms.internal.ads.oq, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2455oq implements InterfaceC1840ah {
    public final HashSet a = new HashSet();
    public final Context b;
    public final C2098gd c;

    public C2455oq(Context context, C2098gd c2098gd) {
        this.b = context;
        this.c = c2098gd;
    }

    /* JADX WARN: Removed duplicated region for block: B:78:0x00ce A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.os.Bundle a() {
        /*
            Method dump skipped, instructions count: 430
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2455oq.a():android.os.Bundle");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1840ah
    public final synchronized void m0(zze zzeVar) {
        if (zzeVar.a != 3) {
            C2098gd c2098gd = this.c;
            HashSet hashSet = this.a;
            synchronized (c2098gd.a) {
                c2098gd.e.addAll(hashSet);
            }
        }
    }
}
