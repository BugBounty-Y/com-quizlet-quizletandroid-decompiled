package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;

/* renamed from: com.google.android.gms.internal.ads.my, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2377my implements InterfaceC2506py {
    public final String a;
    public final C2604sA b;
    public final BA c;
    public final int d;
    public final Yz e;
    public final Integer f;

    public C2377my(String str, C2604sA c2604sA, BA ba, int i, Yz yz, Integer num) {
        this.a = str;
        this.b = c2604sA;
        this.c = ba;
        this.d = i;
        this.e = yz;
        this.f = num;
    }

    public static C2377my a(String str, BA ba, int i, Yz yz, Integer num) throws GeneralSecurityException {
        if (yz == Yz.RAW) {
            if (num != null) {
                throw new GeneralSecurityException("Keys with output prefix type raw should not have an id requirement.");
            }
        } else if (num == null) {
            throw new GeneralSecurityException("Keys with output prefix type different from raw should have an id requirement.");
        }
        return new C2377my(str, AbstractC2677ty.a(str), ba, i, yz, num);
    }
}
