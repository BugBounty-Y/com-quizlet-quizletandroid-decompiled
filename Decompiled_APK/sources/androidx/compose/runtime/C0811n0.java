package androidx.compose.runtime;

import kotlin.KotlinNothingValueException;

/* renamed from: androidx.compose.runtime.n0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0811n0 {
    public final AbstractC0809m0 a;
    public final boolean b;
    public final M0 c;
    public final boolean d;
    public final Object e;
    public boolean f = true;

    public C0811n0(AbstractC0809m0 abstractC0809m0, Object obj, boolean z, M0 m0, boolean z2) {
        this.a = abstractC0809m0;
        this.b = z;
        this.c = m0;
        this.d = z2;
        this.e = obj;
    }

    public final Object a() {
        if (this.b) {
            return null;
        }
        Object obj = this.e;
        if (obj != null) {
            return obj;
        }
        r.d("Unexpected form of a provided value");
        throw new KotlinNothingValueException();
    }
}
