package androidx.compose.runtime;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.runtime.m0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0809m0 {
    public final U a;

    public AbstractC0809m0(Function0 function0) {
        this.a = new U(function0);
    }

    public abstract C0811n0 a(Object obj);

    public Z0 b() {
        return this.a;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final Z0 c(C0811n0 c0811n0, Z0 z0) {
        I i = null;
        if (z0 instanceof I) {
            if (c0811n0.d) {
                i = (I) z0;
                ((L0) i.a).setValue(c0811n0.a());
            }
        } else if (z0 instanceof Y0) {
            if ((c0811n0.b || c0811n0.e != null) && !c0811n0.d) {
                Y0 y0 = (Y0) z0;
                if (Intrinsics.b(c0811n0.a(), y0.a)) {
                    i = y0;
                }
            }
        } else if (z0 instanceof C) {
            c0811n0.getClass();
            kotlin.jvm.internal.r rVar = ((C) z0).a;
        }
        if (i != null) {
            return i;
        }
        if (!c0811n0.d) {
            return new Y0(c0811n0.a());
        }
        M0 m0 = c0811n0.c;
        if (m0 == null) {
            m0 = V.f;
        }
        return new I(new ParcelableSnapshotMutableState(c0811n0.e, m0));
    }
}
