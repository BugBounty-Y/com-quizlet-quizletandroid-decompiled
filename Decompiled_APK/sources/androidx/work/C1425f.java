package androidx.work;

import android.net.NetworkRequest;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.work.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1425f {
    public static final C1425f j = new C1425f();
    public final A a;
    public final androidx.work.impl.utils.g b;
    public final boolean c;
    public final boolean d;
    public final boolean e;
    public final boolean f;
    public final long g;
    public final long h;
    public final Set i;

    public C1425f() {
        A requiredNetworkType = A.a;
        Intrinsics.checkNotNullParameter(requiredNetworkType, "requiredNetworkType");
        Intrinsics.checkNotNullParameter(requiredNetworkType, "requiredNetworkType");
        kotlin.collections.M contentUriTriggers = kotlin.collections.M.a;
        Intrinsics.checkNotNullParameter(requiredNetworkType, "requiredNetworkType");
        Intrinsics.checkNotNullParameter(contentUriTriggers, "contentUriTriggers");
        this.b = new androidx.work.impl.utils.g(null);
        this.a = requiredNetworkType;
        this.c = false;
        this.d = false;
        this.e = false;
        this.f = false;
        this.g = -1L;
        this.h = -1L;
        this.i = contentUriTriggers;
    }

    public final boolean a() {
        return !this.i.isEmpty();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !C1425f.class.equals(obj.getClass())) {
            return false;
        }
        C1425f c1425f = (C1425f) obj;
        if (this.c == c1425f.c && this.d == c1425f.d && this.e == c1425f.e && this.f == c1425f.f && this.g == c1425f.g && this.h == c1425f.h && Intrinsics.b(this.b.a, c1425f.b.a) && this.a == c1425f.a) {
            return Intrinsics.b(this.i, c1425f.i);
        }
        return false;
    }

    public final int hashCode() {
        int iHashCode = ((((((((this.a.hashCode() * 31) + (this.c ? 1 : 0)) * 31) + (this.d ? 1 : 0)) * 31) + (this.e ? 1 : 0)) * 31) + (this.f ? 1 : 0)) * 31;
        long j2 = this.g;
        int i = (iHashCode + ((int) (j2 ^ (j2 >>> 32)))) * 31;
        long j3 = this.h;
        int iHashCode2 = (this.i.hashCode() + ((i + ((int) (j3 ^ (j3 >>> 32)))) * 31)) * 31;
        NetworkRequest networkRequest = this.b.a;
        return iHashCode2 + (networkRequest != null ? networkRequest.hashCode() : 0);
    }

    public final String toString() {
        return "Constraints{requiredNetworkType=" + this.a + ", requiresCharging=" + this.c + ", requiresDeviceIdle=" + this.d + ", requiresBatteryNotLow=" + this.e + ", requiresStorageNotLow=" + this.f + ", contentTriggerUpdateDelayMillis=" + this.g + ", contentTriggerMaxDelayMillis=" + this.h + ", contentUriTriggers=" + this.i + ", }";
    }

    public C1425f(androidx.work.impl.utils.g requiredNetworkRequestCompat, A requiredNetworkType, boolean z, boolean z2, boolean z3, boolean z4, long j2, long j3, Set contentUriTriggers) {
        Intrinsics.checkNotNullParameter(requiredNetworkRequestCompat, "requiredNetworkRequestCompat");
        Intrinsics.checkNotNullParameter(requiredNetworkType, "requiredNetworkType");
        Intrinsics.checkNotNullParameter(contentUriTriggers, "contentUriTriggers");
        this.b = requiredNetworkRequestCompat;
        this.a = requiredNetworkType;
        this.c = z;
        this.d = z2;
        this.e = z3;
        this.f = z4;
        this.g = j2;
        this.h = j3;
        this.i = contentUriTriggers;
    }

    public C1425f(C1425f other) {
        Intrinsics.checkNotNullParameter(other, "other");
        this.c = other.c;
        this.d = other.d;
        this.b = other.b;
        this.a = other.a;
        this.e = other.e;
        this.f = other.f;
        this.i = other.i;
        this.g = other.g;
        this.h = other.h;
    }
}
