package androidx.compose.material3;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.material3.m1, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0682m1 {
    public final L3 a;
    public final androidx.compose.runtime.internal.d b;

    public C0682m1(L3 l3, androidx.compose.runtime.internal.d dVar) {
        this.a = l3;
        this.b = dVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0682m1)) {
            return false;
        }
        C0682m1 c0682m1 = (C0682m1) obj;
        return Intrinsics.b(this.a, c0682m1.a) && this.b.equals(c0682m1.b);
    }

    public final int hashCode() {
        L3 l3 = this.a;
        return this.b.hashCode() + ((l3 == null ? 0 : l3.hashCode()) * 31);
    }

    public final String toString() {
        return "FadeInFadeOutAnimationItem(key=" + this.a + ", transition=" + this.b + ')';
    }
}
