package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.vz, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public enum EnumC2764vz implements QA {
    UNKNOWN_HASH(0),
    SHA1(1),
    SHA384(2),
    SHA256(3),
    SHA512(4),
    SHA224(5),
    UNRECOGNIZED(-1);

    public final int a;

    EnumC2764vz(int i2) {
        this.a = i2;
    }

    public final int a() {
        if (this != UNRECOGNIZED) {
            return this.a;
        }
        throw new IllegalArgumentException("Can't get the number of an unknown enum value.");
    }

    @Override // java.lang.Enum
    public final String toString() {
        return Integer.toString(this.a);
    }
}
