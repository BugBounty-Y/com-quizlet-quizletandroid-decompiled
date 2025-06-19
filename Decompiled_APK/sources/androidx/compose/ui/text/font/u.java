package androidx.compose.ui.text.font;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class u implements Comparable {
    public static final u b;
    public static final u c;
    public static final u d;
    public static final u e;
    public static final u f;
    public static final u g;
    public static final u h;
    public static final u i;
    public final int a;

    static {
        u uVar = new u(100);
        u uVar2 = new u(200);
        u uVar3 = new u(300);
        u uVar4 = new u(400);
        b = uVar4;
        u uVar5 = new u(com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR);
        c = uVar5;
        u uVar6 = new u(com.pubmatic.sdk.video.a.GENERAL_COMPANION_AD_ERROR);
        d = uVar6;
        u uVar7 = new u(700);
        e = uVar7;
        u uVar8 = new u(800);
        u uVar9 = new u(com.pubmatic.sdk.video.a.UNDEFINED_ERROR);
        f = uVar4;
        g = uVar5;
        h = uVar6;
        i = uVar7;
        kotlin.collections.B.j(uVar, uVar2, uVar3, uVar4, uVar5, uVar6, uVar7, uVar8, uVar9);
    }

    public u(int i2) {
        this.a = i2;
        if (1 > i2 || i2 >= 1001) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i2, "Font weight can be in range [1, 1000]. Current value: ").toString());
        }
    }

    @Override // java.lang.Comparable
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public final int compareTo(u uVar) {
        return Intrinsics.g(this.a, uVar.a);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof u) {
            return this.a == ((u) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return this.a;
    }

    public final String toString() {
        return android.support.v4.media.session.a.q(new StringBuilder("FontWeight(weight="), this.a, ')');
    }
}
