package com.google.android.gms.internal.fido;

/* renamed from: com.google.android.gms.internal.fido.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2938b extends AbstractC2940d {
    public static final C2938b a = new C2938b();

    @Override // com.google.android.gms.internal.fido.AbstractC2940d
    public final Object a() {
        throw new IllegalStateException("Optional.get() cannot be called on an absent value");
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2940d
    public final boolean b() {
        return false;
    }

    public final boolean equals(Object obj) {
        return obj == this;
    }

    public final int hashCode() {
        return 2040732332;
    }

    public final String toString() {
        return "Optional.absent()";
    }
}
