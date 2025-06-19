package com.sdk.growthbook.utils;

import com.ionspin.kotlin.bignum.integer.c;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class FNV {

    @NotNull
    private final c INIT32 = new c(2166136261L);

    @NotNull
    private final c PRIME32 = new c(16777619);

    @NotNull
    private final c MOD32 = new c(2).l(32);

    @NotNull
    public final c fnv1a32(@NotNull String data) {
        Intrinsics.checkNotNullParameter(data, "data");
        c cVarM = this.INIT32;
        int length = data.length();
        for (int i = 0; i < length; i++) {
            c other = new c(data.charAt(i) & 255);
            cVarM.getClass();
            Intrinsics.checkNotNullParameter(other, "other");
            long[] jArrA = c.c.A(cVarM.a, other.a);
            Intrinsics.checkNotNullParameter(cVarM, "this");
            int i2 = 1;
            boolean z = cVarM.n() < 0;
            Intrinsics.checkNotNullParameter(other, "this");
            if (z ^ (other.n() < 0)) {
                i2 = 2;
            } else if (c.e(jArrA)) {
                i2 = 3;
            }
            c cVarH = new c(jArrA, i2).h(this.PRIME32);
            c other2 = this.MOD32;
            cVarH.getClass();
            Intrinsics.checkNotNullParameter(other2, "modulo");
            Intrinsics.checkNotNullParameter(cVarH, "this");
            Intrinsics.checkNotNullParameter(other2, "other");
            cVarM = cVarH.m(other2);
            if (cVarM.compareTo(0) < 0) {
                cVarM = cVarM.k(other2);
            }
        }
        return cVarM;
    }
}
